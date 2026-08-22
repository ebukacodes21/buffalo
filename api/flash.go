package api

import (
	"encoding/base64"
	"net/http"
	"strings"
)

const flashCookieName = "flash"

func setFlash(w http.ResponseWriter, kind, msg string) {
	http.SetCookie(w, &http.Cookie{
		Name:     flashCookieName,
		Value:    kind + ":" + base64.RawURLEncoding.EncodeToString([]byte(msg)),
		Path:     "/",
		MaxAge:   120,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func popFlash(w http.ResponseWriter, r *http.Request) (string, string) {
	c, err := r.Cookie(flashCookieName)
	if err != nil || c.Value == "" {
		return "", ""
	}

	http.SetCookie(w, &http.Cookie{
		Name:     flashCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	parts := strings.SplitN(c.Value, ":", 2)
	if len(parts) != 2 || (parts[0] != "error" && parts[0] != "success") {
		return "", ""
	}
	msg, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", ""
	}
	return parts[0], string(msg)
}
