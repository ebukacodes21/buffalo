package api

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ebukacodes21/buffalo/service"
	"github.com/ebukacodes21/buffalo/tooling"
	"github.com/golang-jwt/jwt/v4"
)

// The product-scoped member API lets a product like TerraSell manage the
// membership of the signed-in member's own organization. Products relay the
// member's own buffalo access token; every request is scoped to the calling
// member's org, never to someone else's. Role and removal are restricted to
// org owners and admins; any active member may read the roster.

// memberAPIGuard authenticates an active org member (a member-subject token
// with the userinfo audience), mirroring adminAPIGuard but without the
// platform-admin requirement.
func (a *api) memberAPIGuard(next func(http.ResponseWriter, *http.Request, *service.Member)) http.HandlerFunc {
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

		member, err := a.Svc.GetMemberByID(r.Context(), claims.Subject)
		if err != nil {
			writeJSONError(w, http.StatusUnauthorized, "unknown member")
			return
		}
		if !member.IsActive {
			writeJSONError(w, http.StatusForbidden, "account deactivated")
			return
		}

		next(w, r, member)
	}
}

// requireMemberManage allows role/removal mutations for org owners and
// admins only.
func (a *api) requireMemberManage(w http.ResponseWriter, actor *service.Member) bool {
	if actor.Role != "owner" && actor.Role != "admin" {
		writeJSONError(w, http.StatusForbidden, "organization owners and admins only")
		return false
	}
	return true
}

func (a *api) auditMemberAPI(r *http.Request, actor *service.Member, eventType string, details map[string]interface{}) {
	if err := a.Svc.InsertAuditEvent(r.Context(), actor.ID, actor.OrgID, eventType, clientIP(r), r.UserAgent(), details); err != nil {
		fmt.Printf("error writing audit event %s: %v\n", eventType, err)
	}
}

type productMemberRow struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
}

func (a *api) apiProductMembersList(w http.ResponseWriter, r *http.Request, actor *service.Member) {
	members, err := a.Svc.ListMembers(r.Context(), actor.OrgID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	out := make([]productMemberRow, 0, len(members))
	for _, m := range members {
		if q != "" &&
			!strings.Contains(strings.ToLower(m.Name), q) &&
			!strings.Contains(strings.ToLower(m.Email), q) {
			continue
		}
		out = append(out, productMemberRow{
			ID: m.ID, Name: m.Name, Email: m.Email, Role: m.Role,
			IsActive: m.IsActive, CreatedAt: m.CreatedAt,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"org_id":  actor.OrgID,
		"members": out,
	})
}

func (a *api) apiProductMembersAdd(w http.ResponseWriter, r *http.Request, actor *service.Member) {
	if !a.requireMemberManage(w, actor) {
		return
	}
	var req addMemberRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	if req.Role == "" {
		req.Role = "member"
	}
	if req.Role != "owner" && req.Role != "admin" && req.Role != "member" {
		writeJSONError(w, http.StatusBadRequest, "role must be owner, admin or member")
		return
	}
	if req.Email == "" || !strings.Contains(req.Email, "@") {
		writeJSONError(w, http.StatusBadRequest, "email is required")
		return
	}

	// A member is scoped to this org. If one already exists here with this
	// email, reuse it; otherwise create a new member account.
	existing, err := a.Svc.GetMemberByOrgAndEmail(r.Context(), actor.OrgID, req.Email)

	var memberID string
	switch {
	case err == nil:
		memberID = existing.ID
	case strings.Contains(err.Error(), "no rows"):
		if strings.TrimSpace(req.Name) == "" {
			writeJSONError(w, http.StatusBadRequest, "name is required when creating a new member")
			return
		}
		if len(req.Password) < 8 {
			writeJSONError(w, http.StatusBadRequest, "password of at least 8 characters is required when creating a new member")
			return
		}
		hash, err := tooling.HashPassword(req.Password)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		name := strings.TrimSpace(req.Name)
		newMember, err := a.Svc.CreateMember(r.Context(), actor.OrgID, req.Role, req.Email, hash, name,
			firstWord(name), lastWord(name), req.Email)
		if err != nil {
			if err == service.ErrAlreadyMember {
				writeJSONError(w, http.StatusConflict, "a member with that email already exists in this organization")
				return
			}
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		a.auditMemberAPI(r, actor, "member.created", map[string]interface{}{"email": req.Email})
		memberID = newMember.ID
	default:
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	a.auditMemberAPI(r, actor, "member.added", map[string]interface{}{
		"email": req.Email, "role": req.Role,
	})
	writeJSON(w, http.StatusCreated, map[string]string{"member_id": memberID})
}

func (a *api) apiProductMembersRole(w http.ResponseWriter, r *http.Request, actor *service.Member) {
	if !a.requireMemberManage(w, actor) {
		return
	}
	var req roleRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Role != "owner" && req.Role != "admin" && req.Role != "member" {
		writeJSONError(w, http.StatusBadRequest, "role must be owner, admin or member")
		return
	}
	member, ok := a.guardLastOwner(w, r.Context(), actor.OrgID, r.PathValue("memberID"), req.Role)
	if !ok {
		return
	}
	if err := a.Svc.UpdateMemberRole(r.Context(), actor.OrgID, member.ID, req.Role); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.auditMemberAPI(r, actor, "member.role_changed", map[string]interface{}{
		"email": member.Email, "from": member.Role, "to": req.Role,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (a *api) apiProductMembersRemove(w http.ResponseWriter, r *http.Request, actor *service.Member) {
	if !a.requireMemberManage(w, actor) {
		return
	}
	member, ok := a.guardLastOwner(w, r.Context(), actor.OrgID, r.PathValue("memberID"), "")
	if !ok {
		return
	}
	if err := a.Svc.RemoveMember(r.Context(), actor.OrgID, member.ID); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.auditMemberAPI(r, actor, "member.removed", map[string]interface{}{"email": member.Email})
	writeJSON(w, http.StatusOK, map[string]string{"status": "removed"})
}

// changePasswordRequest is the signed-in member asking to update the password
// on their own buffalo account.
type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// apiProductMembersChangePassword lets any active member change their own
// password. The current password must verify against the stored argon2 hash;
// the new one is re-hashed before persisting.
func (a *api) apiProductMembersChangePassword(w http.ResponseWriter, r *http.Request, actor *service.Member) {
	var req changePasswordRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.CurrentPassword == "" {
		writeJSONError(w, http.StatusBadRequest, "current password is required")
		return
	}
	if len(req.NewPassword) < 8 {
		writeJSONError(w, http.StatusBadRequest, "new password must be at least 8 characters")
		return
	}
	if req.NewPassword == req.CurrentPassword {
		writeJSONError(w, http.StatusBadRequest, "new password must differ from the current one")
		return
	}
	if actor.PasswordHash == "" || !tooling.VerifyPassword(actor.PasswordHash, req.CurrentPassword) {
		writeJSONError(w, http.StatusBadRequest, "current password is incorrect")
		return
	}

	hash, err := tooling.HashPassword(req.NewPassword)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := a.Svc.UpdatePasswordHash(r.Context(), actor.ID, hash); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.auditMemberAPI(r, actor, "member.password_changed", map[string]interface{}{"email": actor.Email})
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}
