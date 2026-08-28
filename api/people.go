package api

import (
	"net/http"
	"strings"

	"github.com/ebukacodes21/buffalo/service"
)

// ── People ──

func (a *api) apiUserList(w http.ResponseWriter, r *http.Request, actor *service.User) {
	list, err := a.Svc.ListUsers(r.Context(), strings.TrimSpace(r.URL.Query().Get("q")), 200)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"users": list})
}

type activeRequest struct {
	Active bool `json:"active"`
}

func (a *api) apiUserSetActive(w http.ResponseWriter, r *http.Request, actor *service.User) {
	id := strings.TrimSpace(r.PathValue("id"))
	target, err := a.Svc.GetUserByID(r.Context(), id)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "user not found")
		return
	}
	if target.ID == actor.ID {
		writeJSONError(w, http.StatusConflict, "you cannot deactivate your own account")
		return
	}
	var req activeRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.Svc.SetUserActive(r.Context(), target.ID, req.Active); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	kind := "user.deactivated"
	if req.Active {
		kind = "user.activated"
	}
	a.auditAPI(r, actor, kind, "", map[string]interface{}{"email": target.Email})
	writeJSON(w, http.StatusOK, map[string]bool{"is_active": req.Active})
}
