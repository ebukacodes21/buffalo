package api

import (
	"net/http"
	"strings"

	"github.com/ebukacodes21/buffalo/service"
	"github.com/ebukacodes21/buffalo/tooling"
)

// ── Applications ──

func (a *api) apiAppList(w http.ResponseWriter, r *http.Request, actor *service.User) {
	clients, err := a.Svc.ListClients(r.Context(), strings.TrimSpace(r.URL.Query().Get("q")), 200)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	for i := range clients {
		clients[i].ClientSecret = ""
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"applications": clients})
}

type createAppRequest struct {
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
	BaseURL      string   `json:"base_url"`
}

// newClientCredentials generates a fresh public client_id and secret pair
// for registering an OAuth application.
func newClientCredentials() (clientID, clientSecret string, err error) {
	if clientID, err = randomToken("buf_", 12); err != nil {
		return "", "", err
	}
	if clientSecret, err = randomToken("", 48); err != nil {
		return "", "", err
	}
	return clientID, clientSecret, nil
}

func randomToken(prefix string, n int) (string, error) {
	s, err := tooling.GetRandomString(n)
	if err != nil {
		return "", err
	}
	return prefix + s, nil
}

// apiAppCreate registers a platform product: an OAuth client owned by the
// platform rather than by any single business.
func (a *api) apiAppCreate(w http.ResponseWriter, r *http.Request, actor *service.User) {
	var req createAppRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeJSONError(w, http.StatusBadRequest, "name is required")
		return
	}
	if !safeText(req.Name) || hasScriptMarker(req.Name) {
		writeJSONError(w, http.StatusBadRequest, "name contains characters that aren't allowed")
		return
	}
	clientID, secret, err := newClientCredentials()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	req.BaseURL = strings.TrimRight(strings.TrimSpace(req.BaseURL), "/")
	if req.BaseURL == "" {
		writeJSONError(w, http.StatusBadRequest, "base_url is required")
		return
	}
	if !validateUrl(req.BaseURL) {
		writeJSONError(w, http.StatusBadRequest, "base_url must be an absolute http(s) URL")
		return
	}

	uris := make([]string, 0, len(req.RedirectURIs))
	for _, u := range req.RedirectURIs {
		u = strings.TrimRight(strings.TrimSpace(u), "/")
		if !validateUrl(u) {
			writeJSONError(w, http.StatusBadRequest, "redirect_uri must be an absolute http(s) URL")
			return
		}
		uris = append(uris, u)
	}

	client, err := a.Svc.CreateClient(r.Context(), clientID, secret, req.Name, uris, req.BaseURL)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.auditAPI(r, actor, "app.created", "", map[string]interface{}{
		"name": client.Name, "client_id": client.ClientID,
	})

	client.ClientSecret = ""
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"application":        client,
		"client_secret_once": secret,
	})
}

func (a *api) apiAppDetail(w http.ResponseWriter, r *http.Request, actor *service.User) {
	client, ok := a.loadAppOr404(w, r)
	if !ok {
		return
	}
	client.ClientSecret = ""
	writeJSON(w, http.StatusOK, map[string]interface{}{"application": client})
}

type updateAppRequest struct {
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
	IsActive     bool     `json:"is_active"`
	BaseURL      string   `json:"base_url"`
}

func (a *api) apiAppUpdate(w http.ResponseWriter, r *http.Request, actor *service.User) {
	client, ok := a.loadAppOr404(w, r)
	if !ok {
		return
	}
	var req updateAppRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeJSONError(w, http.StatusBadRequest, "name is required")
		return
	}
	if !safeText(req.Name) || hasScriptMarker(req.Name) {
		writeJSONError(w, http.StatusBadRequest, "name contains characters that aren't allowed")
		return
	}
	req.BaseURL = strings.TrimRight(strings.TrimSpace(req.BaseURL), "/")
	if req.BaseURL == "" {
		req.BaseURL = client.BaseUrl
	} else if !validateUrl(req.BaseURL) {
		writeJSONError(w, http.StatusBadRequest, "base_url must be an absolute http(s) URL")
		return
	}
	uris := client.RedirectUris
	if req.RedirectURIs != nil {
		uris = make([]string, 0, len(req.RedirectURIs))
		for _, u := range req.RedirectURIs {
			u = strings.TrimRight(strings.TrimSpace(u), "/")
			if !validateUrl(u) {
				writeJSONError(w, http.StatusBadRequest, "redirect_uri must be an absolute http(s) URL")
				return
			}
			uris = append(uris, u)
		}
	}
	if err := a.Svc.UpdateClient(r.Context(), client.ID, req.Name, uris, req.IsActive, req.BaseURL); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.auditAPI(r, actor, "app.updated", "", map[string]interface{}{
		"client_id": client.ClientID, "redirect_uris": req.RedirectURIs, "active": req.IsActive,
		"base_url": req.BaseURL,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (a *api) apiAppRotate(w http.ResponseWriter, r *http.Request, actor *service.User) {
	client, ok := a.loadAppOr404(w, r)
	if !ok {
		return
	}
	_, secret, err := newClientCredentials()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := a.Svc.RotateClientSecret(r.Context(), client.ID, secret); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.auditAPI(r, actor, "app.secret_rotated", "", map[string]interface{}{
		"client_id": client.ClientID,
	})
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"client_id":          client.ClientID,
		"client_secret_once": secret,
	})
}
