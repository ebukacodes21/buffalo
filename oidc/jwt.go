package oidc

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"

	"github.com/golang-jwt/jwt/v4"
)

func GetTokenFromCode(endpoint, jwksUrl, redirectUri, clientID, clientSecret, code string) (*jwt.Token, *jwt.RegisteredClaims, error) {
	values := url.Values{}
	values.Add("client_id", clientID)
	values.Add("client_secret", clientSecret)
	values.Add("redirect_uri", redirectUri)
	values.Add("code", code)
	values.Add("grant_type", "authorization_code")

	res, err := http.PostForm(endpoint, values)
	if err != nil {
		return nil, nil, fmt.Errorf("post form error: %v", err)
	}
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("read body error: %v", err)
	}

	if res.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("request not successful: status %d: %s", res.StatusCode, string(data))
	}

	var token Token
	err = json.Unmarshal(data, &token)
	if err != nil {
		return nil, nil, fmt.Errorf("unmarshal token error: %v", err)
	}

	claims := &jwt.RegisteredClaims{}
	_, err = jwt.ParseWithClaims(token.IDToken, claims, func(t *jwt.Token) (interface{}, error) {
		kid, ok := t.Header["kid"]
		if !ok {
			return nil, fmt.Errorf("kid not found")
		}

		pk, err := getPublickeyFromJwks(jwksUrl, kid.(string))
		if err != nil {
			return nil, fmt.Errorf("fetch public key error: %v", err)
		}
		return pk, nil
	})

	if err != nil {
		return nil, nil, fmt.Errorf("token parsing error: %v", err)
	}

	accessClaims := &jwt.RegisteredClaims{}
	parsedAccessToken, err := jwt.ParseWithClaims(token.AccessToken, accessClaims, func(t *jwt.Token) (interface{}, error) {
		kid, ok := t.Header["kid"]
		if !ok {
			return nil, fmt.Errorf("kid not found")
		}

		pk, err := getPublickeyFromJwks(jwksUrl, kid.(string))
		if err != nil {
			return nil, fmt.Errorf("fetch public key error: %v", err)
		}
		return pk, nil
	})

	if err != nil {
		return nil, nil, fmt.Errorf("token parsing error: %v", err)
	}

	return parsedAccessToken, claims, nil
}

func getPublickeyFromJwks(jwksUrl, kid string) (*rsa.PublicKey, error) {
	res, err := http.Get(jwksUrl)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("invalid status code: %d", res.StatusCode)
	}

	var jwks Jwks
	err = json.Unmarshal(data, &jwks)
	if err != nil {
		return nil, err
	}

	for _, key := range jwks.Keys {
		if key.Kid == kid {
			nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
			if err != nil {
				return nil, fmt.Errorf("decode string error: %v", err)
			}

			eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
			if err != nil {
				return nil, fmt.Errorf("decode exponent error: %v", err)
			}
			e := new(big.Int).SetBytes(eBytes)
			if !e.IsInt64() || e.Int64() <= 1 {
				return nil, fmt.Errorf("invalid exponent")
			}

			n := big.NewInt(0)
			n.SetBytes(nBytes)
			return &rsa.PublicKey{
				N: n,
				E: int(e.Int64()),
			}, nil
		}
	}

	return nil, fmt.Errorf("no public key found with kid: %s", kid)
}
