package api

import (
	"buffalo/users"
	"database/sql"
	"fmt"
	"net/http"
)

type api struct {
	PrivateKey []byte
	Config     Config
	Users      *users.Repository
	// pool to store all session payloads on the server
	SessionPool map[string]Payload
	CodePool    map[string]Payload
}

func newApi(privateKey []byte, config Config, db *sql.DB) *api {
	return &api{
		PrivateKey:  privateKey,
		Config:      config,
		Users:       users.NewRepository(db),
		SessionPool: make(map[string]Payload),
		CodePool:    make(map[string]Payload),
	}
}

func Start(httpServer *http.Server, privateKey []byte, config Config, db *sql.DB) error {
	a := newApi(privateKey, config, db)

	mux := http.NewServeMux()
	mux.HandleFunc("/", a.index)
	mux.HandleFunc("/authorization", a.authorization)
	// mux.HandleFunc("/token", a.token)
	mux.HandleFunc("/login", a.login)
	mux.HandleFunc("/forgot-password", a.forgotPassword)
	mux.HandleFunc("/reset-password", a.resetPassword)
	// mux.HandleFunc("/jwkb.json", a.jwks)
	mux.HandleFunc("/.well-known/openid-configuration", a.discovery)
	// mux.HandleFunc("/userinfo", a.userinfo)

	httpServer.Handler = CSRFMiddleware(privateKey, mux)

	return httpServer.ListenAndServe()
}

func apiError(w http.ResponseWriter, code int, err error) {
	w.WriteHeader(code)
	w.Write([]byte(err.Error()))
	fmt.Printf("error: %s\n", err)
}
