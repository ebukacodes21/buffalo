package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/ebukacodes21/buffalo/admin"
)

// productMenu lets a product pull its sidemenu definition using its OAuth
// client credentials — the same confidential-client trust model as /token,
// so no extra service-to-service secret is needed. Items come back in
// display order; the product filters by the caller's paid entitlements.
func (a *api) productMenu(w http.ResponseWriter, r *http.Request) {
	clientID, ok := a.productClientID(w, r)
	if !ok {
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

// productMenuDefinition accepts a product's full baked-in menu tree (Basic
// auth with its OAuth client credentials) and wholesale-replaces the synced
// copy. Console-added rows (source='manual') survive re-syncs.
func (a *api) productMenuDefinition(w http.ResponseWriter, r *http.Request) {
	var clientID string
	if user, pass, ok := r.BasicAuth(); ok {
		clientID = user
		if !a.Admin.ClientCredentialsValid(user, pass) {
			apiError(w, http.StatusUnauthorized, fmt.Errorf("invalid client credentials"))
			return
		}
	} else {
		if err := r.ParseForm(); err != nil {
			apiError(w, http.StatusBadRequest, err)
			return
		}
		clientID = r.PostForm.Get("client_id")
		if clientID == "" || !a.Admin.ClientCredentialsValid(clientID, r.PostForm.Get("client_secret")) {
			apiError(w, http.StatusUnauthorized, fmt.Errorf("invalid client credentials"))
			return
		}
	}

	var body struct {
		Items []admin.SidemenuItem `json:"items"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apiError(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
		return
	}
	items := make([]*admin.SidemenuItem, 0, len(body.Items))
	for _, item := range body.Items {
		item.Label = strings.TrimSpace(item.Label)
		item.Href = strings.TrimSpace(item.Href)
		item.RequiredEntitlement = strings.TrimSpace(item.RequiredEntitlement)
		if item.Label == "" || item.Href == "" {
			apiError(w, http.StatusUnprocessableEntity, fmt.Errorf("every menu item needs label and href"))
			return
		}
		if item.RequiredEntitlement != "" && !validEntitlementKey(item.RequiredEntitlement) {
			apiError(w, http.StatusUnprocessableEntity, fmt.Errorf("invalid entitlement key %q", item.RequiredEntitlement))
			return
		}
		items = append(items, &item)
	}

	if err := a.Admin.ReplaceProductSidemenuItems(clientID, items); err != nil {
		apiError(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"updated": len(items)})
}

// productClientID authenticates a product-facing request via Basic auth or
// form credentials and returns the verified client id.
func (a *api) productClientID(w http.ResponseWriter, r *http.Request) (string, bool) {
	if user, pass, ok := r.BasicAuth(); ok {
		if a.Admin.ClientCredentialsValid(user, pass) {
			return user, true
		}
		apiError(w, http.StatusUnauthorized, fmt.Errorf("invalid client credentials"))
		return "", false
	}
	if err := r.ParseForm(); err != nil {
		apiError(w, http.StatusBadRequest, err)
		return "", false
	}
	clientID := r.PostForm.Get("client_id")
	if clientID == "" || !a.Admin.ClientCredentialsValid(clientID, r.PostForm.Get("client_secret")) {
		apiError(w, http.StatusUnauthorized, fmt.Errorf("invalid client credentials"))
		return "", false
	}
	return clientID, true
}
