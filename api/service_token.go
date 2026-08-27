package api

import (
	"net/http"
	"time"

	"github.com/ebukacodes21/buffalo/tooling"
	"github.com/ebukacodes21/buffalo/users"
	"github.com/golang-jwt/jwt/v4"
)

// serviceTokenTTL keeps console→product calls short-lived: a leaked token
// expires in minutes and never outlives the page request that needed it.
const serviceTokenTTL = 10 * time.Minute

// apiServiceToken mints a short-lived buffalo-signed access token that lets
// the stateless console call one product's platform-facing GET endpoints.
//
// Security model: the console proves platform-admin identity to buffalo with
// its normal bearer token; buffalo then vouches for the machine call. The
// product verifies the JWT with buffalo's public JWKS — the exact pipeline it
// already uses for user logins — and must additionally check aud == its own
// client_id and scope "product:read". No shared static secrets live on either
// side, tokens can't be replayed after expiry, and revocation is as simple as
// deactivating the client.
func (a *api) apiServiceToken(w http.ResponseWriter, r *http.Request, actor *users.User) {
	client, ok := a.loadAppOr404(w, r)
	if !ok {
		return
	}
	if !client.IsActive {
		writeJSONError(w, http.StatusConflict, "application is inactive")
		return
	}

	jti, err := tooling.GetRandomString(24)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":   a.Config.Url,
		"aud":   []string{client.ClientID},
		"sub":   "arkad-console",
		"typ":   "service",
		"scope": "product:read",
		"jti":   jti,
		"iat":   now.Unix(),
		"nbf":   now.Unix(),
		"exp":   now.Add(serviceTokenTTL).Unix(),
	})
	token.Header["kid"] = "buffalo_v1"

	pk, err := jwt.ParseRSAPrivateKeyFromPEM(a.PrivateKey)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	signed, err := token.SignedString(pk)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	a.auditAPI(r, actor, "service_token.issued", "", map[string]interface{}{
		"client_id": client.ClientID, "scope": "product:read",
	})
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"access_token": signed,
		"token_type":   "bearer",
		"expires_in":   int(serviceTokenTTL.Seconds()),
	})
}
