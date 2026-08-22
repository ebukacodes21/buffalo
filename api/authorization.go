package api

import (
	"fmt"
	"log"
	"net/http"

	"github.com/ebukacodes21/buffalo/tooling"
)

func (a *api) authorization(w http.ResponseWriter, r *http.Request) {
	var (
		clientID     string
		redirectURI  string
		responseType string
		state        string
		scope        string
	)

	if clientID = r.URL.Query().Get("client_id"); clientID == "" {
		apiError(w, http.StatusBadRequest, fmt.Errorf("client_id is missing"))
		return
	}

	if redirectURI = r.URL.Query().Get("redirect_uri"); redirectURI == "" {
		apiError(w, http.StatusBadRequest, fmt.Errorf("redirect_uri is missing"))
		return
	}

	if responseType = r.URL.Query().Get("response_type"); responseType != "code" {
		apiError(w, http.StatusBadRequest, fmt.Errorf("response_type is missing"))
		return
	}

	if state = r.URL.Query().Get("state"); state == "" {
		apiError(w, http.StatusBadRequest, fmt.Errorf("state is missing"))
		return
	}

	appConfig := AppConfig{}
	if scope = r.URL.Query().Get("scope"); scope == "" {
		apiError(w, http.StatusBadRequest, fmt.Errorf("scope is missing"))
		return
	}

	for _, app := range a.Config.Apps {
		if app.ClientID == clientID {
			appConfig = app
		}
	}

	// Fall back to clients provisioned through the admin console.
	if appConfig.ClientID == "" {
		client, err := a.Admin.GetActiveClientByClientID(clientID)
		if err != nil {
			log.Printf("dynamic client lookup %q failed: %v", clientID, err)
		}
		if err == nil {
			appConfig = AppConfig{
				ClientID:     client.ClientID,
				ClientSecret: client.ClientSecret,
				Issuer:       a.Config.Url,
				RedirectURIs: client.RedirectURIs,
			}
		}
	}

	if appConfig.ClientID == "" {
		apiError(w, http.StatusNotFound, fmt.Errorf("client_id not found"))
		return
	}

	found := false
	for _, uri := range appConfig.RedirectURIs {
		if uri == redirectURI {
			found = true
		}
	}

	if !found {
		apiError(w, http.StatusNotFound, fmt.Errorf("redirect_uri not whitelisted"))
		return
	}

	sessID, err := tooling.GetRandomString(256)
	if err != nil {
		apiError(w, http.StatusInternalServerError, fmt.Errorf("unable to generate session id"))
		return
	}

	a.SessionPool[sessID] = Payload{
		ClientID:     clientID,
		RedirectURI:  redirectURI,
		ResponseType: responseType,
		Scope:        scope,
		State:        state,
		AppConfig:    appConfig,
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "last_client",
		Value:    clientID,
		Path:     "/",
		MaxAge:   30 * 24 * 60 * 60,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	w.Header().Add("location", fmt.Sprintf("/login?sessionID=%s", sessID))
	w.WriteHeader(http.StatusFound)
}
