package api

import (
	"embed"
	"fmt"
	"io/fs"
	"net/http"

	"github.com/ebukacodes21/buffalo/service"
)

//go:embed static
var staticFs embed.FS

type api struct {
	PrivateKey []byte
	Config     Config
	// pool to store all session payloads on the server
	SessionPool map[string]Payload
	CodePool    map[string]Payload
	Svc         *service.Buffalo
}

func newApi(privateKey []byte, config Config, svc *service.Buffalo) *api {
	return &api{
		PrivateKey:  privateKey,
		Config:      config,
		SessionPool: make(map[string]Payload),
		CodePool:    make(map[string]Payload),
		Svc:         svc,
	}
}

func staticHandler() http.Handler {
	sub, err := fs.Sub(staticFs, "static")
	if err != nil {
		panic(fmt.Sprintf("static assets missing: %v", err))
	}
	return http.StripPrefix("/static/", http.FileServer(http.FS(sub)))
}

func Start(httpServer *http.Server, privateKey []byte, config Config, svc *service.Buffalo) error {
	a := newApi(privateKey, config, svc)

	mux := http.NewServeMux()
	mux.HandleFunc("/", a.index)
	mux.Handle("GET /static/", staticHandler())
	mux.HandleFunc("/health", a.health)
	mux.HandleFunc("/authorization", a.authorization)
	mux.HandleFunc("/token", a.token)
	mux.HandleFunc("/login", a.login)
	mux.HandleFunc("/forgot-password", a.forgotPassword)
	mux.HandleFunc("/reset-password", a.resetPassword)
	mux.HandleFunc("/jwks", a.jwks)
	mux.HandleFunc("/.well-known/openid-configuration", a.discovery)
	mux.HandleFunc("/userinfo", a.userinfo)

	// Admin JSON API (consumed by the Arkad console application)
	mux.HandleFunc("GET /api/admin/stats", a.adminAPIGuard(a.apiStats))
	mux.HandleFunc("GET /api/admin/businesses", a.adminAPIGuard(a.apiBusinessList))
	mux.HandleFunc("POST /api/admin/businesses", a.adminAPIGuard(a.apiBusinessOnboard))
	mux.HandleFunc("GET /api/admin/businesses/{id}", a.adminAPIGuard(a.apiBusinessDetail))
	mux.HandleFunc("POST /api/admin/businesses/{id}/status", a.adminAPIGuard(a.apiBusinessStatus))
	mux.HandleFunc("POST /api/admin/businesses/{id}/entitlements", a.adminAPIGuard(a.apiBusinessEntitlements))
	mux.HandleFunc("POST /api/admin/businesses/{id}/members/add", a.adminAPIGuard(a.apiMemberAdd))
	mux.HandleFunc("POST /api/admin/businesses/{id}/members/{memberID}/role", a.adminAPIGuard(a.apiMemberRole))
	mux.HandleFunc("POST /api/admin/businesses/{id}/members/{memberID}/remove", a.adminAPIGuard(a.apiMemberRemove))
	mux.HandleFunc("GET /api/admin/apps", a.adminAPIGuard(a.apiAppList))
	mux.HandleFunc("POST /api/admin/apps", a.adminAPIGuard(a.apiAppCreate))
	mux.HandleFunc("GET /api/admin/apps/{id}", a.adminAPIGuard(a.apiAppDetail))
	mux.HandleFunc("POST /api/admin/apps/{id}/service-token", a.adminAPIGuard(a.apiServiceToken))
	mux.HandleFunc("POST /api/admin/apps/{id}/update", a.adminAPIGuard(a.apiAppUpdate))
	mux.HandleFunc("POST /api/admin/apps/{id}/rotate", a.adminAPIGuard(a.apiAppRotate))
	mux.HandleFunc("GET /api/admin/users", a.adminAPIGuard(a.apiUserList))
	mux.HandleFunc("POST /api/admin/users/{id}/active", a.adminAPIGuard(a.apiUserSetActive))
	mux.HandleFunc("GET /api/admin/audit", a.adminAPIGuard(a.apiAuditList))

	// Product-scoped member API (products like TerraSell relay the signed-in
	// member's own token; requests are scoped to that member's org)
	mux.HandleFunc("GET /api/product/members", a.memberAPIGuard(a.apiProductMembersList))
	mux.HandleFunc("POST /api/product/members", a.memberAPIGuard(a.apiProductMembersAdd))
	mux.HandleFunc("POST /api/product/members/{memberID}/role", a.memberAPIGuard(a.apiProductMembersRole))
	mux.HandleFunc("POST /api/product/members/{memberID}/remove", a.memberAPIGuard(a.apiProductMembersRemove))
	mux.HandleFunc("POST /api/product/members/me/password", a.memberAPIGuard(a.apiProductMembersChangePassword))

	httpServer.Handler = CSRFMiddleware(privateKey, mux)

	return httpServer.ListenAndServe()
}

func apiError(w http.ResponseWriter, code int, err error) {
	w.WriteHeader(code)
	w.Write([]byte(err.Error()))
	fmt.Printf("error: %s\n", err)
}

// health backs the healthCheckPath declared in render.yaml.
func (a *api) health(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}
