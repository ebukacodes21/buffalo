package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/ebukacodes21/buffalo/admin"
	"github.com/ebukacodes21/buffalo/oidc"
	"github.com/ebukacodes21/buffalo/tooling"
	"github.com/ebukacodes21/buffalo/users"

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
	if err := a.Users.CreateRefreshToken(refreshToken, payload.ClientID, payload.User.ID, payload.Scope, time.Now().Add(refreshTokenTTL)); err != nil {
		apiError(w, http.StatusInternalServerError, fmt.Errorf("unable to store refresh token"))
		return
	}

	delete(a.CodePool, r.PostForm.Get("code"))

	out, err := json.Marshal(a.issueTokens(payload, refreshToken))
	if err != nil {
		apiError(w, http.StatusInternalServerError, fmt.Errorf("token marshalling error: %v", err))
		return
	}
	w.Write(out)
}

// tokenFromRefresh rotates a refresh token and issues fresh tokens without
// user interaction. The presented token is revoked on use.
func (a *api) tokenFromRefresh(w http.ResponseWriter, r *http.Request) {
	presented := r.PostForm.Get("refresh_token")
	clientID := r.PostForm.Get("client_id")

	client, userID, scope, err := a.Users.GetRefreshToken(presented)
	if err != nil {
		apiError(w, http.StatusBadRequest, fmt.Errorf("invalid refresh token"))
		return
	}
	if clientID == "" || clientID != client {
		apiError(w, http.StatusBadRequest, fmt.Errorf("client_id mismatch"))
		return
	}

	user, err := a.Users.GetByID(userID)
	if err != nil || !user.IsActive {
		apiError(w, http.StatusBadRequest, fmt.Errorf("invalid refresh token"))
		return
	}

	payload := Payload{
		ClientID:     client,
		Scope:        scope,
		CodeIssuedAt: time.Now(),
		User: users.User{
			Sub:   user.ID,
			ID:    user.ID,
			Name:  user.Name,
			Email: user.Email,
		},
	}
	if roles, err := a.Users.GetOrgRoles(user.ID); err == nil {
		payload.User.Roles = roles
	}
	if orgs, err := a.Admin.ListMembershipsForUser(user.ID); err == nil {
		payload.Organizations = orgs
	}

	replacement, err := tooling.GetRandomString(64)
	if err != nil {
		apiError(w, http.StatusInternalServerError, fmt.Errorf("unable to generate refresh token"))
		return
	}
	if err := a.Users.RevokeRefreshToken(presented); err != nil {
		apiError(w, http.StatusInternalServerError, fmt.Errorf("unable to revoke refresh token"))
		return
	}
	if err := a.Users.CreateRefreshToken(replacement, client, userID, scope, time.Now().Add(refreshTokenTTL)); err != nil {
		apiError(w, http.StatusInternalServerError, fmt.Errorf("unable to store refresh token"))
		return
	}

	out, err := json.Marshal(a.issueTokens(payload, replacement))
	if err != nil {
		apiError(w, http.StatusInternalServerError, fmt.Errorf("token marshalling error: %v", err))
		return
	}
	w.Write(out)
}

// issueTokens signs the id + access token pair for a resolved session.
func (a *api) issueTokens(payload Payload, refreshToken string) oidc.Token {
	pk, err := jwt.ParseRSAPrivateKeyFromPEM(a.PrivateKey)
	if err != nil {
		return oidc.Token{}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub":   payload.User.Sub,
		"iss":   a.Config.Url,
		"aud":   payload.ClientID,
		"email": payload.User.Email,
		"name":  payload.User.Name,
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
		"nbf":   time.Now().Unix(),
		"iat":   time.Now().Unix(),
	})
	token.Header["kid"] = "buffalo_v1"
	sigIdToken, err := token.SignedString(pk)
	if err != nil {
		return oidc.Token{}
	}

	if payload.Organizations == nil {
		payload.Organizations = []admin.OrgMembership{}
	}

	token = jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub":           payload.User.Sub,
		"iss":           a.Config.Url,
		"aud":           []string{fmt.Sprintf("%s/userinfo", a.Config.Url)},
		"email":         payload.User.Email,
		"roles":         payload.User.Roles,
		"organizations": payload.Organizations,
		"name":          payload.User.Name,
		"exp":           time.Now().Add(1 * time.Hour).Unix(),
		"nbf":           time.Now().Unix(),
		"iat":           time.Now().Unix(),
	})
	token.Header["kid"] = "buffalo_v1"
	sigAccessToken, err := token.SignedString(pk)
	if err != nil {
		return oidc.Token{}
	}

	return oidc.Token{
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
