package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v4"
)

func (a *api) userinfo(w http.ResponseWriter, r *http.Request) {
	authHeader := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if authHeader == "" {
		apiError(w, http.StatusUnauthorized, fmt.Errorf("authorization header missing"))
		return
	}

	claims := &jwt.RegisteredClaims{}
	_, err := jwt.ParseWithClaims(authHeader, claims, func(t *jwt.Token) (interface{}, error) {
		privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(a.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("parse private key error: %v", err)
		}
		return &privateKey.PublicKey, nil
	})
	if err != nil {
		apiError(w, http.StatusUnauthorized, fmt.Errorf("invalid token"))
		return
	}

	found := false
	for _, aud := range claims.Audience {
		if aud == fmt.Sprintf("%s/userinfo", a.Config.Url) {
			found = true
		}
	}
	if !found {
		apiError(w, http.StatusForbidden, fmt.Errorf("token has incorrect audience"))
		return
	}

	user, err := a.Users.GetByID(claims.Subject)
	if err != nil {
		apiError(w, http.StatusNotFound, fmt.Errorf("user not found"))
		return
	}

	roles, err := a.Users.GetOrgRoles(claims.Subject)
	if err != nil {
		apiError(w, http.StatusInternalServerError, fmt.Errorf("roles lookup error"))
		return
	}

	orgs, err := a.Admin.ListMembershipsForUser(claims.Subject)
	if err != nil {
		apiError(w, http.StatusInternalServerError, fmt.Errorf("organizations lookup error"))
		return
	}

	out, err := json.Marshal(map[string]any{
		"sub":                user.ID,
		"email":              user.Email,
		"email_verified":     user.EmailVerified,
		"name":               user.Name,
		"given_name":         user.GivenName,
		"family_name":        user.FamilyName,
		"preferred_username": user.PreferredUsername,
		"picture":            user.Picture,
		"is_platform_admin":  user.IsPlatformAdmin,
		"roles":              roles,
		"organizations":      orgs,
	})
	if err != nil {
		apiError(w, http.StatusInternalServerError, fmt.Errorf("userinfo marshalling error"))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(out)
}
