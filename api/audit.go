package api

import (
	"net/http"
	"strings"

	"github.com/ebukacodes21/buffalo/service"
)

// ── Audit ──

func (a *api) apiAuditList(w http.ResponseWriter, r *http.Request, actor *service.User) {
	events, err := a.Svc.ListAuditEvents(r.Context(), strings.TrimSpace(r.URL.Query().Get("org_id")), 200)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"events": events})
}
