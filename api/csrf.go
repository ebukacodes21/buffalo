package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"

	"buffalo/tooling"
)

type csrfContextKey struct{}

func CSRFMiddleware(privateKey []byte, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var token, sig string

		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			token, _ = tooling.GetRandomString(32)
			mac := hmac.New(sha256.New, privateKey)
			mac.Write([]byte(token))
			sig = base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

			http.SetCookie(w, &http.Cookie{
				Name:     "csrf_token",
				Value:    token,
				Path:     "/",
				MaxAge:   3600,
				HttpOnly: false,
				SameSite: http.SameSiteLaxMode,
			})
			http.SetCookie(w, &http.Cookie{
				Name:     "csrf_sig",
				Value:    sig,
				Path:     "/",
				MaxAge:   3600,
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			})
		} else {
			// Validate on state-changing methods
			cookieToken, err1 := r.Cookie("csrf_token")
			cookieSig, err2 := r.Cookie("csrf_sig")
			if err1 != nil || err2 != nil {
				http.Error(w, "missing csrf token", http.StatusForbidden)
				return
			}
			token = cookieToken.Value
			sig = cookieSig.Value

			mac := hmac.New(sha256.New, privateKey)
			mac.Write([]byte(token))
			expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
			if !hmac.Equal([]byte(sig), []byte(expectedSig)) {
				http.Error(w, "invalid csrf token", http.StatusForbidden)
				return
			}

			// Check form field if present (fetch requests rely on cookie only)
			if r.Method == http.MethodPost {
				if err := r.ParseForm(); err == nil {
					if formToken := r.PostForm.Get("csrf_token"); formToken != "" && formToken != token {
						http.Error(w, "csrf token mismatch", http.StatusForbidden)
						return
					}
				}
			}
		}

		ctx := context.WithValue(r.Context(), csrfContextKey{}, token)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func CSRFToken(r *http.Request) string {
	if v, ok := r.Context().Value(csrfContextKey{}).(string); ok {
		return v
	}
	return ""
}
