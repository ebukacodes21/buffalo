package api

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// productMenu lets a product pull its sidemenu definition using its OAuth
// client credentials — the same confidential-client trust model as /token,
// so no extra service-to-service secret is needed. Items come back in
// display order; the product filters by the caller's paid entitlements.
func (a *api) productMenu(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	clientID := r.PostForm.Get("client_id")
	clientSecret := r.PostForm.Get("client_secret")
	if clientID == "" || !a.Admin.ClientCredentialsValid(clientID, clientSecret) {
		apiError(w, http.StatusUnauthorized, fmt.Errorf("invalid client credentials"))
		return
	}

	items, err := a.Admin.ListSidemenuItems(clientID, true)
	if err != nil {
		apiError(w, http.StatusInternalServerError, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"items": items})
}
