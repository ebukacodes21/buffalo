package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/ebukacodes21/buffalo/service"
	"github.com/ebukacodes21/buffalo/tooling"
)

type addMemberRequest struct {
	Email        string `json:"email"`
	Name         string `json:"name"`
	Password     string `json:"password"`
	Role         string `json:"role"`
	SupervisorID string `json:"supervisor_id"`
}

func (a *api) apiMemberAdd(w http.ResponseWriter, r *http.Request, actor *service.User) {
	org, ok := a.loadOrgOr404(w, r)
	if !ok {
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
	if !validEmail(req.Email) {
		writeJSONError(w, http.StatusBadRequest, "email is not a valid email address")
		return
	}

	// A member is scoped to this org. If one already exists here with this
	// email, reuse it; otherwise create a new member account.
	existing, err := a.Svc.GetMemberByOrgAndEmail(r.Context(), org.ID, req.Email)

	var memberID string
	switch {
	case err == nil:
		memberID = existing.ID
	case strings.Contains(err.Error(), "no rows"):
		name := strings.TrimSpace(req.Name)
		if name == "" {
			writeJSONError(w, http.StatusBadRequest, "name is required when creating a new member")
			return
		}
		if !lettersOnly(name) || hasScriptMarker(name) {
			writeJSONError(w, http.StatusBadRequest, "name may only contain letters, spaces and . ' - & ( )")
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
		newMember, err := a.Svc.CreateMember(r.Context(), org.ID, req.Role, req.Email, hash, name,
			firstWord(name), lastWord(name), req.Email)
		if err != nil {
			if err == service.ErrAlreadyMember {
				writeJSONError(w, http.StatusConflict, "a member with that email already exists in this organization")
				return
			}
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		a.auditAPI(r, actor, "member.created", org.ID, map[string]interface{}{"email": req.Email})
		memberID = newMember.ID
	default:
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	a.auditAPI(r, actor, "member.added", org.ID, map[string]interface{}{
		"email": req.Email, "role": req.Role,
	})
	writeJSON(w, http.StatusCreated, map[string]string{"member_id": memberID})
}

func (a *api) guardLastOwner(w http.ResponseWriter, ctx context.Context, orgID, memberID, nextRole string) (*service.Member, bool) {
	member, err := a.Svc.GetMember(ctx, orgID, memberID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "member not found")
		return nil, false
	}
	losingOwner := member.Role == "owner" && nextRole != "owner"
	if losingOwner || nextRole == "remove-owner-check" {
		count, err := a.Svc.CountOwners(ctx, orgID)
		if err == nil && count <= 1 && (losingOwner || member.Role == "owner") {
			writeJSONError(w, http.StatusConflict, "a business must keep at least one owner")
			return nil, false
		}
	}
	return member, true
}

type roleRequest struct {
	Role string `json:"role"`
}

func (a *api) apiMemberRole(w http.ResponseWriter, r *http.Request, actor *service.User) {
	org, ok := a.loadOrgOr404(w, r)
	if !ok {
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
	member, ok := a.guardLastOwner(w, r.Context(), org.ID, r.PathValue("memberID"), req.Role)
	if !ok {
		return
	}
	if err := a.Svc.UpdateMemberRole(r.Context(), org.ID, member.ID, req.Role); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.auditAPI(r, actor, "member.role_changed", org.ID, map[string]interface{}{
		"email": member.Email, "from": member.Role, "to": req.Role,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (a *api) apiMemberRemove(w http.ResponseWriter, r *http.Request, actor *service.User) {
	org, ok := a.loadOrgOr404(w, r)
	if !ok {
		return
	}
	member, ok := a.guardLastOwner(w, r.Context(), org.ID, r.PathValue("memberID"), "")
	if !ok {
		return
	}
	if err := a.Svc.RemoveMember(r.Context(), org.ID, member.ID); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.auditAPI(r, actor, "member.removed", org.ID, map[string]interface{}{"email": member.Email})
	writeJSON(w, http.StatusOK, map[string]string{"status": "removed"})
}
