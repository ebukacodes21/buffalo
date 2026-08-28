package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v4"
)

func (a *api) userinfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	authHeader := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if authHeader == "" {
		apiError(w, http.StatusUnauthorized, fmt.Errorf("authorization header missing"))
		return
	}

	claims := &jwt.MapClaims{}
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
	for _, aud := range (*claims)["aud"].([]interface{}) {
		if aud == fmt.Sprintf("%s/userinfo", a.Config.Url) {
			found = true
		}
	}
	if !found {
		apiError(w, http.StatusForbidden, fmt.Errorf("token has incorrect audience"))
		return
	}

	sub, _ := (*claims)["sub"].(string)
	subType, _ := (*claims)["sub_type"].(string)

	if subType == "member" {
		m, err := a.Svc.GetMemberByID(ctx, sub)
		if err != nil {
			apiError(w, http.StatusNotFound, fmt.Errorf("member not found"))
			return
		}
		org, err := a.Svc.ListMembershipForMember(ctx, sub)
		if err != nil {
			apiError(w, http.StatusInternalServerError, fmt.Errorf("organizations lookup error"))
			return
		}
		out, err := json.Marshal(map[string]any{
			"sub":                m.ID,
			"org_id":             m.OrgID,
			"role":               m.Role,
			"email":              m.Email,
			"email_verified":     m.EmailVerified,
			"name":               m.Name,
			"given_name":         m.GivenName,
			"family_name":        m.FamilyName,
			"preferred_username": m.PreferredUsername,
			"picture":            m.Picture,
			"is_platform_admin":  false,
			"roles":              rolesForMember(m.Role),
			"organization":       org,
		})
		if err != nil {
			apiError(w, http.StatusInternalServerError, fmt.Errorf("userinfo marshalling error"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(out)
		return
	}

	user, err := a.Svc.GetUserByID(ctx, sub)
	if err != nil {
		apiError(w, http.StatusNotFound, fmt.Errorf("user not found"))
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
		"roles":              []string{},
	})
	if err != nil {
		apiError(w, http.StatusInternalServerError, fmt.Errorf("userinfo marshalling error"))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(out)
}

func rolesForMember(role string) []string {
	if role == "" {
		return []string{}
	}
	return []string{role}
}
