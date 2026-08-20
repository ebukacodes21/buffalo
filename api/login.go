package api

import (
	"buffalo/tooling"
	"buffalo/users"
	"embed"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"time"
)

//go:embed templates/*.html
var templateFs embed.FS

var funcMap = template.FuncMap{}

func parseTemplate(name string) (*template.Template, error) {
	return template.New("").Funcs(funcMap).ParseFS(
		templateFs,
		"templates/base.html",
		"templates/"+name,
	)
}

func (a *api) login(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			apiError(w, http.StatusBadRequest, fmt.Errorf("parse form error: %s", err))
			return
		}

		sessID := r.PostForm.Get("sessionID")
		payload, ok := a.SessionPool[sessID]
		if !ok {
			apiError(w, http.StatusNotFound, fmt.Errorf("session not found"))
			return
		}

		login := r.PostForm.Get("login")
		password := r.PostForm.Get("password")

		user, err := a.Users.GetByEmail(login)
		if err != nil {
			apiError(w, http.StatusUnauthorized, fmt.Errorf("invalid credentials"))
			return
		}

		if !user.IsActive {
			apiError(w, http.StatusUnauthorized, fmt.Errorf("account is inactive"))
			return
		}

		if !users.VerifyPassword(user.PasswordHash, password) {
			apiError(w, http.StatusUnauthorized, fmt.Errorf("invalid credentials"))
			return
		}

		code, err := tooling.GetRandomString(128)
		if err != nil {
			apiError(w, http.StatusInternalServerError, fmt.Errorf("error generating code: %s", err))
			return
		}

		payload.CodeIssuedAt = time.Now()
		payload.User = users.User{
			Sub:               user.ID,
			ID:                user.ID,
			Name:              user.Name,
			GivenName:         user.GivenName,
			FamilyName:        user.FamilyName,
			PreferredUsername: user.PreferredUsername,
			Email:             user.Email,
			Picture:           user.Picture,
		}
		a.CodePool[code] = payload

		if r.PostForm.Get("remember") == "on" {
			refreshToken, err := tooling.GetRandomString(64)
			if err != nil {
				apiError(w, http.StatusInternalServerError, fmt.Errorf("error generating refresh token: %s", err))
				return
			}
			if err := a.Users.CreateRefreshToken(refreshToken, payload.ClientID, user.ID, payload.Scope, time.Now().Add(30*24*time.Hour)); err != nil {
				apiError(w, http.StatusInternalServerError, fmt.Errorf("error storing refresh token: %s", err))
				return
			}
			http.SetCookie(w, &http.Cookie{
				Name:     "refresh_token",
				Value:    refreshToken,
				Path:     "/",
				MaxAge:   30 * 24 * 60 * 60,
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			})
		}

		delete(a.SessionPool, sessID)
		w.Header().Add("location", fmt.Sprintf("%s?code=%s&state=%s", payload.RedirectURI, code, payload.State))
		w.WriteHeader(http.StatusFound)
		return
	}

	sessID := r.URL.Query().Get("sessionID")
	if sessID == "" {
		apiError(w, http.StatusBadRequest, fmt.Errorf("missing sessionID"))
		return
	}

	tmpl, err := parseTemplate("login.html")
	if err != nil {
		apiError(w, http.StatusInternalServerError, fmt.Errorf("template error: %v", err))
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.ExecuteTemplate(w, "layout", map[string]string{
		"SessionID": sessID,
		"CSRFToken": CSRFToken(r),
	})
}

func (a *api) forgotPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			apiError(w, http.StatusBadRequest, fmt.Errorf("parse form error: %s", err))
			return
		}

		email := r.PostForm.Get("email")
		user, err := a.Users.GetByEmail(email)
		if err != nil {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("If an account exists with that email, you will receive a password reset link."))
			return
		}

		token, err := tooling.GetRandomString(64)
		if err != nil {
			apiError(w, http.StatusInternalServerError, fmt.Errorf("error generating token: %s", err))
			return
		}

		if err := a.Users.CreatePasswordReset(user.ID, token, time.Now().Add(1*time.Hour)); err != nil {
			apiError(w, http.StatusInternalServerError, fmt.Errorf("error creating reset token: %s", err))
			return
		}

		log.Printf("PASSWORD RESET for %s: %s/reset-password?token=%s", user.Email, a.Config.Url, token)

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("If an account exists with that email, you will receive a password reset link."))
		return
	}

	tmpl, err := parseTemplate("forgot-password.html")
	if err != nil {
		apiError(w, http.StatusInternalServerError, fmt.Errorf("template error: %v", err))
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.ExecuteTemplate(w, "layout", map[string]string{
		"CSRFToken": CSRFToken(r),
	})
}

func (a *api) resetPassword(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" && r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			apiError(w, http.StatusBadRequest, fmt.Errorf("parse form error: %s", err))
			return
		}
		token = r.PostForm.Get("token")
	}

	if token == "" {
		apiError(w, http.StatusBadRequest, fmt.Errorf("missing token"))
		return
	}

	if r.Method == http.MethodPost {
		password := r.PostForm.Get("password")
		confirm := r.PostForm.Get("confirm")

		data := map[string]interface{}{
			"Token":     token,
			"Error":     "",
			"CSRFToken": CSRFToken(r),
		}

		if password == "" || len(password) < 8 {
			data["Error"] = "Password must be at least 8 characters"
			renderTemplate(w, "reset-password.html", r, data)
			return
		}

		if password != confirm {
			data["Error"] = "Passwords do not match"
			renderTemplate(w, "reset-password.html", r, data)
			return
		}

		userID, err := a.Users.GetPasswordReset(token)
		if err != nil {
			data["Error"] = "Invalid or expired reset link"
			renderTemplate(w, "reset-password.html", r, data)
			return
		}

		hash, err := users.HashPassword(password)
		if err != nil {
			apiError(w, http.StatusInternalServerError, fmt.Errorf("error hashing password: %s", err))
			return
		}

		if err := a.Users.UpdatePasswordHash(userID, hash); err != nil {
			apiError(w, http.StatusInternalServerError, fmt.Errorf("error updating password: %s", err))
			return
		}

		if err := a.Users.MarkPasswordResetUsed(token); err != nil {
			log.Printf("warning: failed to mark reset token used: %v", err)
		}

		http.Redirect(w, r, "/login?reset=success", http.StatusFound)
		return
	}

	renderTemplate(w, "reset-password.html", r, map[string]interface{}{
		"Token":     token,
		"Error":     "",
		"CSRFToken": CSRFToken(r),
	})
}

func renderTemplate(w http.ResponseWriter, name string, r *http.Request, data interface{}) {
	tmpl, err := parseTemplate(name)
	if err != nil {
		apiError(w, http.StatusInternalServerError, fmt.Errorf("template error: %v", err))
		return
	}
	d := data.(map[string]interface{})
	d["CSRFToken"] = CSRFToken(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.ExecuteTemplate(w, "layout", d)
}
