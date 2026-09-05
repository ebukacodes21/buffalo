package api

import (
	"strings"
	"time"

	"net/http"

	"github.com/ebukacodes21/buffalo/service"
	"github.com/ebukacodes21/buffalo/tooling"
)

// mobileLogin is the JSON login used by the TerraSell mobile app: it trades
// valid member credentials for a fresh access/refresh token pair, bypassing
// the interactive browser code-exchange entirely. Buffalo stays the source
// of truth for identity and password verification.
func (a *api) mobileLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		ClientID string `json:"client_id"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	login := strings.ToLower(strings.TrimSpace(req.Email))
	password := req.Password
	clientID := strings.TrimSpace(req.ClientID)

	if login == "" || password == "" {
		writeJSONError(w, http.StatusBadRequest, "email and password are required")
		return
	}
	if !validEmail(login) || hasScriptMarker(login) {
		writeJSONError(w, http.StatusUnauthorized, "invalid email or password")
		return
	}

	client, err := a.Svc.GetActiveClientByClientID(ctx, clientID)
	if err != nil || client.ClientID == "" {
		writeJSONError(w, http.StatusUnauthorized, "unknown client")
		return
	}

	rec, err := a.Svc.LookupEmail(ctx, login)
	if err != nil || !tooling.VerifyPassword(rec.Password, password) {
		writeJSONError(w, http.StatusUnauthorized, "invalid email or password")
		return
	}
	if !rec.IsActive {
		writeJSONError(w, http.StatusForbidden, "This account is inactive. Please contact support.")
		return
	}

	payload := Payload{
		ClientID:    clientID,
		Scope:       "openid offline_access",
		SubjectType: rec.SubjectType,
		Record: &service.AccountRecord{
			Sub:      rec.ID,
			ID:       rec.ID,
			Name:     rec.Name,
			Email:    rec.Email,
			Role:     rec.Role,
			IsActive: rec.IsActive,
		},
	}
	if rec.SubjectType == "member" {
		if org, err := a.Svc.ListMembershipForMember(ctx, rec.ID); err == nil {
			payload.Organization = org
		}
	}

	refreshToken, err := tooling.GetRandomString(64)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "unable to issue refresh token")
		return
	}
	if err := a.Svc.CreateRefreshToken(refreshToken, clientID, payload.SubjectType, payload.SubjectID(), payload.Scope, time.Now().Add(refreshTokenTTL)); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "unable to store refresh token")
		return
	}

	writeJSON(w, http.StatusOK, a.issueTokens(payload, refreshToken))
}