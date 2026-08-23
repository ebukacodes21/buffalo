package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/ebukacodes21/buffalo/admin"
	"github.com/ebukacodes21/buffalo/oidc"

	"github.com/golang-jwt/jwt/v4"
)

func (a *api) token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		apiError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
		return
	}

	if err := r.ParseForm(); err != nil {
		apiError(w, http.StatusBadRequest, fmt.Errorf("parse form error"))
		return
	}

	if r.PostForm.Get("grant_type") != "authorization_code" {
		apiError(w, http.StatusBadRequest, fmt.Errorf("invalid authorization type"))
		return
	}

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

	if payload.AppConfig.ClientSecret != r.PostForm.Get("client_secret") {
		apiError(w, http.StatusBadRequest, fmt.Errorf("invalid client_secret"))
		return
	}

	if payload.RedirectURI != r.PostForm.Get("redirect_uri") {
		apiError(w, http.StatusBadRequest, fmt.Errorf("redirect_uri mismatch"))
		return
	}

	pk, err := jwt.ParseRSAPrivateKeyFromPEM(a.PrivateKey)
	if err != nil {
		apiError(w, http.StatusInternalServerError, fmt.Errorf("private key parsing error: %v", err))
		return
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
		apiError(w, http.StatusInternalServerError, fmt.Errorf("token signing error: %v", err))
		return
	}

	if payload.Organizations == nil {
		payload.Organizations = []admin.OrgMembership{}
	}

	//access token
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
		apiError(w, http.StatusInternalServerError, fmt.Errorf("token signing error: %v", err))
		return
	}

	tokenOutput := oidc.Token{
		AccessToken: sigAccessToken,
		IDToken:     sigIdToken,
		TokenType:   "bearer",
		ExpiresIn:   60,
	}

	delete(a.CodePool, r.PostForm.Get("code"))

	out, err := json.Marshal(tokenOutput)
	if err != nil {
		apiError(w, http.StatusInternalServerError, fmt.Errorf("token marshalling error: %v", err))
		return
	}

	w.Write(out)
}
