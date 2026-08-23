package api

import (
	"embed"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ebukacodes21/buffalo/tooling"
	"github.com/ebukacodes21/buffalo/users"
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
			a.loginError(w, r, "", "Something went wrong. Please try again.")
			return
		}

		sessID := r.PostForm.Get("sessionID")
		payload, ok := a.SessionPool[sessID]
		if !ok {
			a.loginError(w, r, "", "Your sign-in session has expired. Please restart the sign-in from the application.")
			return
		}

		login := r.PostForm.Get("login")
		password := r.PostForm.Get("password")

		user, err := a.Users.GetByEmail(login)
		if err != nil || !users.VerifyPassword(user.PasswordHash, password) {
			a.loginError(w, r, sessID, "Invalid email or password.")
			return
		}

		if !user.IsActive {
			a.loginError(w, r, sessID, "This account is inactive. Please contact support.")
			return
		}

		code, err := tooling.GetRandomString(128)
		if err != nil {
			log.Printf("error generating code: %s", err)
			a.loginError(w, r, sessID, "Something went wrong. Please try again.")
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
		if roles, err := a.Users.GetOrgRoles(user.ID); err != nil {
			log.Printf("error loading roles for %s: %s", user.ID, err)
		} else {
			payload.User.Roles = roles
		}
		if orgs, err := a.Admin.ListMembershipsForUser(user.ID); err != nil {
			log.Printf("error loading org memberships for %s: %s", user.ID, err)
		} else {
			payload.Organizations = orgs
		}
		a.CodePool[code] = payload

		if r.PostForm.Get("remember") == "on" {
			refreshToken, err := tooling.GetRandomString(64)
			if err != nil {
				log.Printf("error generating refresh token: %s", err)
				a.loginError(w, r, sessID, "Something went wrong. Please try again.")
				return
			}
			if err := a.Users.CreateRefreshToken(refreshToken, payload.ClientID, user.ID, payload.Scope, time.Now().Add(30*24*time.Hour)); err != nil {
				log.Printf("error storing refresh token: %s", err)
				a.loginError(w, r, sessID, "Something went wrong. Please try again.")
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

	errMsg := ""
	if kind, msg := popFlash(w, r); kind == "error" {
		errMsg = msg
	} else if sessID == "" {
		errMsg = "Missing sign-in session. Please start the sign-in from the application."
	}

	a.renderLogin(w, r, sessID, errMsg)
}

// loginError implements post/redirect/get: the message is stored in a
// one-shot flash cookie and the browser is bounced to a GET of the login
// page, so refreshing cannot resubmit credentials.
func (a *api) loginError(w http.ResponseWriter, r *http.Request, sessID, msg string) {
	setFlash(w, "error", msg)
	location := "/login"
	if sessID != "" {
		location += "?sessionID=" + url.QueryEscape(sessID)
	}
	http.Redirect(w, r, location, http.StatusSeeOther)
}

func (a *api) renderLogin(w http.ResponseWriter, r *http.Request, sessID, errMsg string) {
	renderTemplate(w, "login.html", r, map[string]interface{}{
		"SessionID": sessID,
		"Error":     errMsg,
	})
}

const resetLinkSentMsg = "If an account exists with that email, you will receive a password reset link."

func (a *api) forgotPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			a.renderForgotPassword(w, r, "", "Something went wrong. Please try again.")
			return
		}

		email := r.PostForm.Get("email")
		user, err := a.Users.GetByEmail(email)
		if err != nil {
			a.forgotPasswordResponse(w, r, resetLinkSentMsg, "")
			return
		}

		token, err := tooling.GetRandomString(64)
		if err != nil {
			log.Printf("error generating reset token: %s", err)
			a.forgotPasswordResponse(w, r, "", "Something went wrong. Please try again.")
			return
		}

		if err := a.Users.CreatePasswordReset(user.ID, token, time.Now().Add(1*time.Hour)); err != nil {
			log.Printf("error storing reset token: %s", err)
			a.forgotPasswordResponse(w, r, "", "Something went wrong. Please try again.")
			return
		}

		log.Printf("PASSWORD RESET for %s: %s/reset-password?token=%s", user.Email, a.Config.Url, token)

		a.forgotPasswordResponse(w, r, resetLinkSentMsg, "")
		return
	}

	a.renderForgotPassword(w, r, "", "")
}

// forgotPasswordResponse answers the fetch() call from the page with plain
// text, or re-renders the full page when the form was submitted without JS.
func (a *api) forgotPasswordResponse(w http.ResponseWriter, r *http.Request, successMsg, errMsg string) {
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		a.renderForgotPassword(w, r, successMsg, errMsg)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if errMsg != "" {
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	w.Write([]byte(map[bool]string{true: successMsg, false: errMsg}[errMsg == ""]))
}

func (a *api) renderForgotPassword(w http.ResponseWriter, r *http.Request, successMsg, errMsg string) {
	renderTemplate(w, "forgot-password.html", r, map[string]interface{}{
		"Success": successMsg,
		"Error":   errMsg,
	})
}

func (a *api) resetPassword(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" && r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			log.Printf("parse form error: %s", err)
			a.resetPasswordError(w, r, token, "Something went wrong. Please try again.")
			return
		}
		token = r.PostForm.Get("token")
	}

	if token == "" {
		a.resetPasswordError(w, r, token, "Invalid or expired reset link. Please request a new one.")
		return
	}

	if r.Method == http.MethodPost {
		password := r.PostForm.Get("password")
		confirm := r.PostForm.Get("confirm")

		fail := func(msg string) {
			a.resetPasswordError(w, r, token, msg)
		}

		if password == "" || len(password) < 8 {
			fail("Password must be at least 8 characters")
			return
		}

		if password != confirm {
			fail("Passwords do not match")
			return
		}

		userID, err := a.Users.GetPasswordReset(token)
		if err != nil {
			fail("Invalid or expired reset link. Please request a new one.")
			return
		}

		hash, err := users.HashPassword(password)
		if err != nil {
			log.Printf("error hashing password: %s", err)
			fail("Something went wrong. Please try again.")
			return
		}

		if err := a.Users.UpdatePasswordHash(userID, hash); err != nil {
			log.Printf("error updating password: %s", err)
			fail("Something went wrong. Please try again.")
			return
		}

		if err := a.Users.MarkPasswordResetUsed(token); err != nil {
			log.Printf("warning: failed to mark reset token used: %v", err)
		}

		http.Redirect(w, r, "/login?reset=success", http.StatusSeeOther)
		return
	}

	errMsg := ""
	if kind, msg := popFlash(w, r); kind == "error" {
		errMsg = msg
	} else if _, err := a.Users.GetPasswordReset(token); err != nil {
		errMsg = "Invalid or expired reset link. Please request a new one."
	}
	renderTemplate(w, "reset-password.html", r, map[string]interface{}{
		"Token":     token,
		"Error":     errMsg,
		"CSRFToken": CSRFToken(r),
	})
}

func (a *api) resetPasswordError(w http.ResponseWriter, r *http.Request, token, msg string) {
	setFlash(w, "error", msg)
	http.Redirect(w, r, "/reset-password?token="+url.QueryEscape(token), http.StatusSeeOther)
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
