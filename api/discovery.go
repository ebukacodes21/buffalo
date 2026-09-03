package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/ebukacodes21/buffalo/service"
)

func (a *api) discovery(w http.ResponseWriter, _ *http.Request) {
	discovery := service.Discovery{
		Issuer:                            a.Config.Url,
		AuthorizationEndpoint:             fmt.Sprintf("%s/authorization", a.Config.Url),
		TokenEndpoint:                     fmt.Sprintf("%s/token", a.Config.Url),
		UserinfoEndpoint:                  fmt.Sprintf("%s/userinfo", a.Config.Url),
		JwksURI:                           fmt.Sprintf("%s/jwks", a.Config.Url),
		ScopesSupported:                   []string{"oidc", "openid", "offline_access"},
		ResponseTypesSupported:            []string{"code"},
		ResponseModesSupported:            []string{"query"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"RS256"},
		TokenEndpointAuthMethodsSupported: []string{"none"},
		CodeChallengeMethodsSupported:     []string{"S256", "plain"},
	}

	o, err := json.Marshal(discovery)
	if err != nil {
		apiError(w, http.StatusInternalServerError, fmt.Errorf("unable to marshal discovery"))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(o)
}
