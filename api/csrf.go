package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/ebukacodes21/buffalo/tooling"
)

type csrfContextKey struct{}

func CSRFMiddleware(privateKey []byte, next http.Handler) http.Handler {
	sign := func(token string) string {
		mac := hmac.New(sha256.New, privateKey)
		mac.Write([]byte(token))
		return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Browser flows only. Bearer-token endpoints (the JSON admin API,
		// userinfo, jwks) authenticate via Authorization headers.
		path := r.URL.Path
		if path == "/token" || strings.HasPrefix(path, "/api/") ||
			path == "/userinfo" || path == "/jwks" || strings.HasPrefix(path, "/.well-known/") {
			next.ServeHTTP(w, r)
			return
		}

		var token, sig string

		cookieToken, err1 := r.Cookie("csrf_token")
		cookieSig, err2 := r.Cookie("csrf_sig")
		validPair := err1 == nil && err2 == nil && cookieToken.Value != "" &&
			hmac.Equal([]byte(cookieSig.Value), []byte(sign(cookieToken.Value)))

		switch {
		case validPair:
			token, sig = cookieToken.Value, cookieSig.Value
		case r.Method == http.MethodGet || r.Method == http.MethodHead:
			var err error
			if token, err = tooling.GetRandomString(32); err != nil {
				http.Error(w, "error generating csrf token", http.StatusInternalServerError)
				return
			}
			sig = sign(token)

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
		default:
			if err1 != nil || err2 != nil {
				http.Error(w, "missing csrf token", http.StatusForbidden)
				return
			}
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
