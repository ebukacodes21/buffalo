package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/ebukacodes21/buffalo/service"
	"github.com/golang-jwt/jwt/v4"
)

// The admin API is consumed by the Arkad console (a separate application).
// Requests must carry a buffalo-issued access token whose subject belongs to
// an active platform admin. Buffalo stays the source of truth; the console
// only renders and relays.
func (a *api) adminAPIGuard(next func(http.ResponseWriter, *http.Request, *service.User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		header := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if header == "" || header == r.Header.Get("Authorization") {
			writeJSONError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}

		claims := &jwt.RegisteredClaims{}
		_, err := jwt.ParseWithClaims(header, claims, func(t *jwt.Token) (interface{}, error) {
			pk, err := jwt.ParseRSAPrivateKeyFromPEM(a.PrivateKey)
			if err != nil {
				return nil, fmt.Errorf("parse private key error: %v", err)
			}
			return &pk.PublicKey, nil
		})
		if err != nil {
			writeJSONError(w, http.StatusUnauthorized, "invalid token")
			return
		}

		expectedAud := fmt.Sprintf("%s/userinfo", a.Config.Url)
		found := false
		for _, aud := range claims.Audience {
			if aud == expectedAud {
				found = true
			}
		}
		if !found {
			writeJSONError(w, http.StatusForbidden, "token has incorrect audience")
			return
		}

		user, err := a.Svc.GetUserByID(r.Context(), claims.Subject)
		if err != nil {
			writeJSONError(w, http.StatusUnauthorized, "unknown user")
			return
		}
		if !user.IsActive {
			writeJSONError(w, http.StatusForbidden, "account deactivated")
			return
		}
		if !user.IsPlatformAdmin {
			writeJSONError(w, http.StatusForbidden, "platform admin access required")
			return
		}

		next(w, r, user)
	}
}

func writeJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if payload != nil {
		_ = json.NewEncoder(w).Encode(payload)
	}
}

func writeJSONError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func readJSON(r *http.Request, dst interface{}) error {
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	return nil
}

func (a *api) auditAPI(r *http.Request, actor *service.User, eventType, orgID string, details map[string]interface{}) {
	if err := a.Svc.InsertAuditEvent(r.Context(), actor.ID, orgID, eventType, clientIP(r), r.UserAgent(), details); err != nil {
		fmt.Printf("error writing audit event %s: %v\n", eventType, err)
	}
}

func (a *api) loadOrgOr404(w http.ResponseWriter, r *http.Request) (*service.Organization, bool) {
	id := strings.TrimSpace(r.PathValue("id"))
	org, err := a.Svc.GetOrgByID(r.Context(), id)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "business not found")
		return nil, false
	}

	return org, true
}

func (a *api) loadAppOr404(w http.ResponseWriter, r *http.Request) (*service.OauthClient, bool) {
	client, err := a.Svc.GetClientByID(r.Context(), r.PathValue("id"))
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "application not found")
		return nil, false
	}
	return client, true
}

// ── small helpers ──

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if net.ParseIP(host) == nil {
		return ""
	}
	return host
}

func firstWord(s string) string {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func lastWord(s string) string {
	fields := strings.Fields(s)
	if len(fields) < 2 {
		return ""
	}
	return fields[len(fields)-1]
}

// validateUrl accepts http(s) URLs without query strings or fragments.
func validateUrl(s string) bool {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	return u.Scheme == "https" || u.Scheme == "http"
}
