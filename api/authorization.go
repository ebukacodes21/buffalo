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

	if scope = r.URL.Query().Get("scope"); scope == "" {
		apiError(w, http.StatusBadRequest, fmt.Errorf("scope is missing"))
		return
	}

// PKCE is optional for confidential clients but the only viable mode for
// public ones (mobile apps) — they cannot hold a client secret.
codeChallenge := r.URL.Query().Get("code_challenge")
codeChallengeMethod := r.URL.Query().Get("code_challenge_method")
if codeChallenge != "" {
	if codeChallengeMethod == "" {
		codeChallengeMethod = "plain"
	}
	if codeChallengeMethod != "S256" && codeChallengeMethod != "plain" {
		apiError(w, http.StatusBadRequest, fmt.Errorf("unsupported code_challenge_method"))
		return
	}
}

// Bridge the OIDC nonce across the authorization + token legs so the id_token
// can echo it back. Missing when the client didn't send one.
nonce := r.URL.Query().Get("nonce")

	// OAuth clients live in the database (managed via the Arkad console).
	appConfig := AppConfig{}
	client, err := a.Svc.GetActiveClientByClientID(r.Context(), clientID)
	if err != nil {
		log.Printf("client lookup %q failed: %v", clientID, err)
	}
	if err == nil {
		appConfig = AppConfig{
			ClientID:     client.ClientID,
			ClientSecret: client.ClientSecret,
			Issuer:       a.Config.Url,
			RedirectURIs: client.RedirectUris,
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
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		ResponseType:        responseType,
		Scope:               scope,
		State:               state,
		AppConfig:           appConfig,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		Nonce:               nonce,
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
