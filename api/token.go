package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/ebukacodes21/buffalo/service"
	"github.com/ebukacodes21/buffalo/tooling"

	"github.com/golang-jwt/jwt/v4"
)

const refreshTokenTTL = 30 * 24 * time.Hour

func (a *api) token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		apiError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
		return
	}

	if err := r.ParseForm(); err != nil {
		apiError(w, http.StatusBadRequest, fmt.Errorf("parse form error"))
		return
	}

	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		a.tokenFromCode(w, r)
	case "refresh_token":
		a.tokenFromRefresh(w, r)
	default:
		apiError(w, http.StatusBadRequest, fmt.Errorf("invalid authorization type"))
	}
}

// tokenFromCode exchanges an authorization code for tokens. Confidential
// clients authenticate with client_secret; public clients (mobile) present a
// PKCE code_verifier bound to the code at /authorization time.
func (a *api) tokenFromCode(w http.ResponseWriter, r *http.Request) {
	payload, ok := a.CodePool[r.PostForm.Get("code")]
	if !ok {
		apiError(w, http.StatusBadRequest, fmt.Errorf("invalid code"))
		return
	}

	if time.Now().After(payload.CodeIssuedAt.Add(2 * time.Minute)) {
		apiError(w, http.StatusBadRequest, fmt.Errorf("code expired"))
		return
	}

	if payload.ClientID != r.PostForm.Get("client_id") {
		apiError(w, http.StatusBadRequest, fmt.Errorf("client_id mismatch"))
		return
	}

	if payload.RedirectURI != r.PostForm.Get("redirect_uri") {
		apiError(w, http.StatusBadRequest, fmt.Errorf("redirect_uri mismatch"))
		return
	}

	if payload.CodeChallenge != "" {
		verifier := r.PostForm.Get("code_verifier")
		if !verifyPKCE(payload.CodeChallenge, payload.CodeChallengeMethod, verifier) {
			apiError(w, http.StatusBadRequest, fmt.Errorf("pkce verification failed"))
			return
		}
	} else if payload.AppConfig.ClientSecret != r.PostForm.Get("client_secret") {
		apiError(w, http.StatusBadRequest, fmt.Errorf("invalid client_secret"))
		return
	}

	refreshToken, err := tooling.GetRandomString(64)
	if err != nil {
		apiError(w, http.StatusInternalServerError, fmt.Errorf("unable to generate refresh token"))
		return
	}
	if err := a.Svc.CreateRefreshToken(refreshToken, payload.ClientID, payload.SubjectType, payload.SubjectID(), payload.Scope, time.Now().Add(refreshTokenTTL)); err != nil {
		apiError(w, http.StatusInternalServerError, fmt.Errorf("unable to store refresh token"))
		return
	}

	delete(a.CodePool, r.PostForm.Get("code"))

	out, err := json.Marshal(a.issueTokens(payload, refreshToken))
	if err != nil {
		apiError(w, http.StatusInternalServerError, fmt.Errorf("token marshalling error: %v", err))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(out)
}

// tokenFromRefresh rotates a refresh token and issues fresh tokens without
// user interaction. The presented token is revoked on use.
func (a *api) tokenFromRefresh(w http.ResponseWriter, r *http.Request) {
	presented := r.PostForm.Get("refresh_token")
	clientID := r.PostForm.Get("client_id")

	client, subjectType, subjectID, scope, err := a.Svc.GetRefreshToken(presented)
	if err != nil {
		apiError(w, http.StatusBadRequest, fmt.Errorf("invalid refresh token"))
		return
	}
	if clientID == "" || clientID != client {
		apiError(w, http.StatusBadRequest, fmt.Errorf("client_id mismatch"))
		return
	}

	payload, err := a.resolvePayload(r.Context(), subjectType, subjectID, client, scope)
	if err != nil {
		apiError(w, http.StatusBadRequest, fmt.Errorf("invalid refresh token"))
		return
	}
	if !payload.IsActive() {
		apiError(w, http.StatusBadRequest, fmt.Errorf("invalid refresh token"))
		return
	}

	replacement, err := tooling.GetRandomString(64)
	if err != nil {
		apiError(w, http.StatusInternalServerError, fmt.Errorf("unable to generate refresh token"))
		return
	}
	if err := a.Svc.RevokeRefreshToken(presented); err != nil {
		apiError(w, http.StatusInternalServerError, fmt.Errorf("unable to revoke refresh token"))
		return
	}
	if err := a.Svc.CreateRefreshToken(replacement, client, subjectType, subjectID, scope, time.Now().Add(refreshTokenTTL)); err != nil {
		apiError(w, http.StatusInternalServerError, fmt.Errorf("unable to store refresh token"))
		return
	}

	out, err := json.Marshal(a.issueTokens(payload, replacement))
	if err != nil {
		apiError(w, http.StatusInternalServerError, fmt.Errorf("token marshalling error: %v", err))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(out)
}

// resolvePayload reconstructs a session Payload for a principal given its
// subject type and id. Members additionally get their org memberships and
// roles loaded for the token claims.
func (a *api) resolvePayload(ctx context.Context, subjectType, subjectID, clientID, scope string) (Payload, error) {
	payload := Payload{
		ClientID:     clientID,
		Scope:        scope,
		SubjectType:  subjectType,
		CodeIssuedAt: time.Now(),
	}
	if subjectType == "member" {
		m, err := a.Svc.GetMemberByID(ctx, subjectID)
		if err != nil {
			return Payload{}, err
		}
		payload.Record = &service.AccountRecord{
			Sub:      m.ID,
			ID:       m.ID,
			Email:    m.Email,
			Name:     m.Name,
			Role:     m.Role,
			IsActive: m.IsActive,
		}
		if org, err := a.Svc.ListMembershipForMember(ctx, m.ID); err == nil {
			payload.Organization = org
		}
		return payload, nil
	}

	u, err := a.Svc.GetUserByID(ctx, subjectID)
	if err != nil {
		return Payload{}, err
	}
	payload.Record = &service.AccountRecord{
		Sub:      u.ID,
		ID:       u.ID,
		Name:     u.Name,
		Email:    u.Email,
		Role:     "platform",
		IsActive: u.IsActive,
	}
	return payload, nil
}

// issueTokens signs the id + access token pair for a resolved session.
func (a *api) issueTokens(payload Payload, refreshToken string) service.Token {
	pk, err := jwt.ParseRSAPrivateKeyFromPEM(a.PrivateKey)
	if err != nil {
		return service.Token{}
	}

	sub := payload.SubjectID()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub":   sub,
		"iss":   a.Config.Url,
		"aud":   payload.ClientID,
		"email": payload.SubjectEmail(),
		"name":  payload.SubjectName(),
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
		"nbf":   time.Now().Unix(),
		"iat":   time.Now().Unix(),
	})
	if payload.Nonce != "" {
		token.Claims.(jwt.MapClaims)["nonce"] = payload.Nonce
	}
	token.Header["kid"] = "buffalo_v1"
	sigIdToken, err := token.SignedString(pk)
	if err != nil {
		return service.Token{}
	}

	roles := payload.SubjectRoles()
	if roles == nil {
		roles = []string{}
	}
	if payload.Organization == nil {
		payload.Organization = &service.Organization{}
	}

	token = jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub":          sub,
		"iss":          a.Config.Url,
		"aud":          []string{fmt.Sprintf("%s/userinfo", a.Config.Url)},
		"email":        payload.SubjectEmail(),
		"roles":        roles,
		"organization": payload.Organization,
		"name":         payload.SubjectName(),
		"sub_type":     payload.SubjectType,
		"exp":          time.Now().Add(1 * time.Hour).Unix(),
		"nbf":          time.Now().Unix(),
		"iat":          time.Now().Unix(),
	})
	token.Header["kid"] = "buffalo_v1"
	sigAccessToken, err := token.SignedString(pk)
	if err != nil {
		return service.Token{}
	}

	return service.Token{
		AccessToken:  sigAccessToken,
		IDToken:      sigIdToken,
		TokenType:    "bearer",
		RefreshToken: refreshToken,
		ExpiresIn:    int(time.Until(time.Now().Add(1 * time.Hour)).Seconds()),
	}
}

// verifyPKCE checks a code_verifier against the challenge stored with the
// authorization code (RFC 7636 section 4.6).
func verifyPKCE(challenge, method, verifier string) bool {
	if verifier == "" || len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	computed := verifier
	if method == "S256" {
		sum := sha256.Sum256([]byte(verifier))
		computed = base64.RawURLEncoding.EncodeToString(sum[:])
	}
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}
