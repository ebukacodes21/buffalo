package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/ebukacodes21/buffalo/service"
	"github.com/golang-jwt/jwt/v4"
)

func (a *api) jwks(w http.ResponseWriter, r *http.Request) {
	pk, err := jwt.ParseRSAPrivateKeyFromPEM(a.PrivateKey)
	if err != nil {
		apiError(w, http.StatusInternalServerError, fmt.Errorf("private key parsing error: %v", err))
		return
	}

	pubKey := pk.PublicKey

	jwks := service.Jwks{
		Keys: []service.JwksKey{
			{
				Kid: "buffalo_v1",
				Alg: "RS256",
				Kty: "RSA",
				Use: "sig",
				N:   base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes()),
				E:   "AQAB",
			},
		},
	}

	out, err := json.Marshal(jwks)
	if err != nil {
		apiError(w, http.StatusInternalServerError, fmt.Errorf("marshal key error: %v", err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(out)
}
