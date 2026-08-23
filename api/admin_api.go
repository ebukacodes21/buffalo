package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/ebukacodes21/buffalo/admin"
	"github.com/ebukacodes21/buffalo/tooling"
	"github.com/ebukacodes21/buffalo/users"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

// The admin API is consumed by the Arkad console (a separate application).
// Requests must carry a buffalo-issued access token whose subject belongs to
// an active platform admin. Buffalo stays the source of truth; the console
// only renders and relays.
func (a *api) adminAPIGuard(next func(http.ResponseWriter, *http.Request, *users.User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		header := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if header == "" || header == r.Header.Get("Authorization") {
			writeJSONError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}

		claims := &jwt.RegisteredClaims{}
		_, err := jwt.ParseWithClaims(header, claims, func(t *jwt.Token) (interface{}, error) {
			pk, err := jwt.ParseRSAPrivateKeyFromPEM(a.PrivateKey)
			if err != nil {
				return nil, fmt.Errorf("parse private key error: %v", err)
			}
			return &pk.PublicKey, nil
		})
		if err != nil {
			writeJSONError(w, http.StatusUnauthorized, "invalid token")
			return
		}

		expectedAud := fmt.Sprintf("%s/userinfo", a.Config.Url)
		found := false
		for _, aud := range claims.Audience {
			if aud == expectedAud {
				found = true
			}
		}
		if !found {
			writeJSONError(w, http.StatusForbidden, "token has incorrect audience")
			return
		}

		user, err := a.Users.GetByID(claims.Subject)
		if err != nil {
			writeJSONError(w, http.StatusUnauthorized, "unknown user")
			return
		}
		if !user.IsActive {
			writeJSONError(w, http.StatusForbidden, "account deactivated")
			return
		}
		if !user.IsPlatformAdmin {
			writeJSONError(w, http.StatusForbidden, "platform admin access required")
			return
		}

		next(w, r, user)
	}
}

func writeJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if payload != nil {
		_ = json.NewEncoder(w).Encode(payload)
	}
}

func writeJSONError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func readJSON(r *http.Request, dst interface{}) error {
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	return nil
}

func (a *api) auditAPI(r *http.Request, actor *users.User, eventType, orgID string, details map[string]interface{}) {
	if err := a.Admin.InsertAuditEvent(actor.ID, orgID, eventType, details, clientIP(r), r.UserAgent()); err != nil {
		fmt.Printf("error writing audit event %s: %v\n", eventType, err)
	}
}

// ── Stats ──

func (a *api) apiStats(w http.ResponseWriter, r *http.Request, actor *users.User) {
	stats, err := a.Admin.Stats()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	events, _ := a.Admin.ListAuditEvents("", 10)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"stats":        stats,
		"recent_audit": events,
	})
}

// ── Businesses ──

func (a *api) apiBusinessList(w http.ResponseWriter, r *http.Request, actor *users.User) {
	orgs, err := a.Admin.ListOrgs(strings.TrimSpace(r.URL.Query().Get("q")), 200)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"businesses": orgs})
}

type onboardRequest struct {
	Name          string `json:"name"`
	Slug          string `json:"slug"`
	OwnerName     string `json:"owner_name"`
	OwnerEmail    string `json:"owner_email"`
	OwnerPassword string `json:"owner_password"`
}

func (a *api) apiBusinessOnboard(w http.ResponseWriter, r *http.Request, actor *users.User) {
	var req onboardRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	req.OwnerEmail = strings.ToLower(strings.TrimSpace(req.OwnerEmail))
	req.OwnerName = strings.TrimSpace(req.OwnerName)

	if req.Name == "" || req.OwnerEmail == "" || req.OwnerName == "" {
		writeJSONError(w, http.StatusBadRequest, "name, owner_name and owner_email are required")
		return
	}
	if !strings.Contains(req.OwnerEmail, "@") {
		writeJSONError(w, http.StatusBadRequest, "owner_email is not a valid email address")
		return
	}

	password := req.OwnerPassword
	generated := false
	if password == "" {
		var err error
		if password, err = tooling.GetRandomString(14); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "could not generate owner password")
			return
		}
		generated = true
	} else if len(password) < 8 {
		writeJSONError(w, http.StatusBadRequest, "owner_password must be at least 8 characters")
		return
	}

	slug := admin.Slugify(firstNonEmpty(req.Slug, req.Name))

	result, err := a.Admin.OnboardBusiness(admin.OnboardInput{
		OrgName:       req.Name,
		Slug:          slug,
		OwnerName:     req.OwnerName,
		OwnerEmail:    req.OwnerEmail,
		OwnerPassword: password,
	})
	if err == admin.ErrSlugTaken {
		writeJSONError(w, http.StatusConflict, fmt.Sprintf("slug %q is already taken", slug))
		return
	}
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	a.auditAPI(r, actor, "org.created", result.Org.ID, map[string]interface{}{
		"name": result.Org.Name, "slug": result.Org.Slug, "owner": req.OwnerEmail,
	})

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"organization":     result.Org,
		"owner_membership": result.Member,
		"owner_credentials": map[string]interface{}{
			"email":     req.OwnerEmail,
			"password":  password,
			"generated": generated,
		},
	})
}

func (a *api) loadOrgOr404(w http.ResponseWriter, r *http.Request) (*admin.Organization, bool) {
	org, err := a.Admin.GetOrg(r.PathValue("id"))
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "business not found")
		return nil, false
	}
	return org, true
}

type businessDetail struct {
	Organization *admin.Organization `json:"organization"`
	Entitlements []string            `json:"entitlements"`
	Members      []admin.Member      `json:"members"`
	Audit        []admin.AuditEvent  `json:"audit"`
}

func (a *api) apiBusinessDetail(w http.ResponseWriter, r *http.Request, actor *users.User) {
	org, ok := a.loadOrgOr404(w, r)
	if !ok {
		return
	}
	entitlements, _ := a.Admin.ListEntitlements(org.ID)
	members, _ := a.Admin.ListMembers(org.ID)
	events, _ := a.Admin.ListAuditEvents(org.ID, 20)

	writeJSON(w, http.StatusOK, businessDetail{
		Organization: org, Entitlements: entitlements, Members: members, Audit: events,
	})
}

type entitlementsRequest struct {
	Entitlements []string `json:"entitlements"`
}

// apiBusinessEntitlements replaces the paid entitlement set for a business.
// The console sends the complete desired list; products observe the change
// via token claims / userinfo and gate their features accordingly.
func (a *api) apiBusinessEntitlements(w http.ResponseWriter, r *http.Request, actor *users.User) {
	org, ok := a.loadOrgOr404(w, r)
	if !ok {
		return
	}
	var req entitlementsRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	items, err := admin.NormalizeEntitlements(req.Entitlements)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	before, err := a.Admin.ListEntitlements(org.ID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := a.Admin.SetEntitlements(org.ID, items); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.auditAPI(r, actor, "org.entitlements_changed", org.ID, map[string]interface{}{
		"from": before, "to": items,
	})
	writeJSON(w, http.StatusOK, map[string]interface{}{"entitlements": items})
}

type statusRequest struct {
	Status string `json:"status"`
}

func (a *api) apiBusinessStatus(w http.ResponseWriter, r *http.Request, actor *users.User) {
	org, ok := a.loadOrgOr404(w, r)
	if !ok {
		return
	}
	var req statusRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Status != "active" && req.Status != "suspended" {
		writeJSONError(w, http.StatusBadRequest, "status must be active or suspended")
		return
	}
	if err := a.Admin.SetOrgStatus(org.ID, req.Status); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.auditAPI(r, actor, "org.status_changed", org.ID, map[string]interface{}{
		"from": org.Status, "to": req.Status,
	})
	org.Status = req.Status
	writeJSON(w, http.StatusOK, map[string]interface{}{"organization": org})
}

type addMemberRequest struct {
	Email    string `json:"email"`
	Name     string `json:"name"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

func (a *api) apiMemberAdd(w http.ResponseWriter, r *http.Request, actor *users.User) {
	org, ok := a.loadOrgOr404(w, r)
	if !ok {
		return
	}
	var req addMemberRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	if req.Role == "" {
		req.Role = "member"
	}
	if req.Role != "owner" && req.Role != "admin" && req.Role != "member" {
		writeJSONError(w, http.StatusBadRequest, "role must be owner, admin or member")
		return
	}
	if req.Email == "" || !strings.Contains(req.Email, "@") {
		writeJSONError(w, http.StatusBadRequest, "email is required")
		return
	}

	userID := ""
	existing, err := a.Users.GetByEmail(req.Email)
	switch {
	case err == nil:
		userID = existing.ID
	case err == users.ErrUserNotFound:
		if strings.TrimSpace(req.Name) == "" {
			writeJSONError(w, http.StatusBadRequest, "name is required when creating a new user")
			return
		}
		if len(req.Password) < 8 {
			writeJSONError(w, http.StatusBadRequest, "password of at least 8 characters is required when creating a new user")
			return
		}
		hash, err := users.HashPassword(req.Password)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		newUser := &users.User{
			ID:                uuid.New().String(),
			Email:             req.Email,
			Name:              strings.TrimSpace(req.Name),
			GivenName:         firstWord(req.Name),
			FamilyName:        lastWord(req.Name),
			PreferredUsername: req.Email,
			PasswordHash:      hash,
			IsActive:          true,
		}
		if err := a.Users.Create(newUser); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		a.auditAPI(r, actor, "user.created", org.ID, map[string]interface{}{"email": req.Email})
		userID = newUser.ID
	default:
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if err := a.Admin.AddMember(org.ID, userID, req.Role); err != nil {
		if err == admin.ErrAlreadyMember {
			writeJSONError(w, http.StatusConflict, "user is already a member of this business")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.auditAPI(r, actor, "member.added", org.ID, map[string]interface{}{
		"email": req.Email, "role": req.Role,
	})
	writeJSON(w, http.StatusCreated, map[string]string{"status": "added"})
}

func (a *api) guardLastOwner(w http.ResponseWriter, orgID, memberID, nextRole string) (*admin.Member, bool) {
	member, err := a.Admin.GetMember(orgID, memberID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "member not found")
		return nil, false
	}
	losingOwner := member.Role == "owner" && nextRole != "owner"
	if losingOwner || nextRole == "remove-owner-check" {
		count, err := a.Admin.CountOwners(orgID)
		if err == nil && count <= 1 && (losingOwner || member.Role == "owner") {
			writeJSONError(w, http.StatusConflict, "a business must keep at least one owner")
			return nil, false
		}
	}
	return member, true
}

type roleRequest struct {
	Role string `json:"role"`
}

func (a *api) apiMemberRole(w http.ResponseWriter, r *http.Request, actor *users.User) {
	org, ok := a.loadOrgOr404(w, r)
	if !ok {
		return
	}
	var req roleRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Role != "owner" && req.Role != "admin" && req.Role != "member" {
		writeJSONError(w, http.StatusBadRequest, "role must be owner, admin or member")
		return
	}
	member, ok := a.guardLastOwner(w, org.ID, r.PathValue("memberID"), req.Role)
	if !ok {
		return
	}
	if err := a.Admin.UpdateMemberRole(org.ID, member.ID, req.Role); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.auditAPI(r, actor, "member.role_changed", org.ID, map[string]interface{}{
		"email": member.Email, "from": member.Role, "to": req.Role,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (a *api) apiMemberRemove(w http.ResponseWriter, r *http.Request, actor *users.User) {
	org, ok := a.loadOrgOr404(w, r)
	if !ok {
		return
	}
	member, ok := a.guardLastOwner(w, org.ID, r.PathValue("memberID"), "")
	if !ok {
		return
	}
	if err := a.Admin.RemoveMember(org.ID, member.ID); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.auditAPI(r, actor, "member.removed", org.ID, map[string]interface{}{"email": member.Email})
	writeJSON(w, http.StatusOK, map[string]string{"status": "removed"})
}

// ── Applications ──

func (a *api) apiAppList(w http.ResponseWriter, r *http.Request, actor *users.User) {
	clients, err := a.Admin.ListClients(strings.TrimSpace(r.URL.Query().Get("q")), 200)
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
}

// apiAppCreate registers a platform product: an OAuth client owned by the
// platform rather than by any single business.
func (a *api) apiAppCreate(w http.ResponseWriter, r *http.Request, actor *users.User) {
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
	clientID, secret, err := admin.NewClientCredentials()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	client := &admin.Client{
		ClientID:     clientID,
		ClientSecret: secret,
		Name:         req.Name,
		RedirectURIs: firstNonEmptySlice(req.RedirectURIs, []string{}),
	}
	if err := a.Admin.CreateClient(client); err != nil {
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

func (a *api) loadAppOr404(w http.ResponseWriter, r *http.Request) (*admin.Client, bool) {
	client, err := a.Admin.GetClient(r.PathValue("id"))
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "application not found")
		return nil, false
	}
	return client, true
}

func (a *api) apiAppDetail(w http.ResponseWriter, r *http.Request, actor *users.User) {
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
}

func (a *api) apiAppUpdate(w http.ResponseWriter, r *http.Request, actor *users.User) {
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
	if err := a.Admin.UpdateClient(client.ID, req.Name, firstNonEmptySlice(req.RedirectURIs, client.RedirectURIs), req.IsActive); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.auditAPI(r, actor, "app.updated", "", map[string]interface{}{
		"client_id": client.ClientID, "redirect_uris": req.RedirectURIs, "active": req.IsActive,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (a *api) apiAppRotate(w http.ResponseWriter, r *http.Request, actor *users.User) {
	client, ok := a.loadAppOr404(w, r)
	if !ok {
		return
	}
	_, secret, err := admin.NewClientCredentials()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := a.Admin.RotateClientSecret(client.ID, secret); err != nil {
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

// ── Product module catalog ──

func (a *api) apiModuleList(w http.ResponseWriter, r *http.Request, actor *users.User) {
	modules, err := a.Admin.ListModules()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"modules": modules})
}

type createModuleRequest struct {
	Namespace string `json:"namespace"`
	Key       string `json:"key"`
	Label     string `json:"label"`
	Hint      string `json:"hint"`
	SortOrder int    `json:"sort_order"`
}

func (a *api) apiModuleCreate(w http.ResponseWriter, r *http.Request, actor *users.User) {
	var req createModuleRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Namespace = strings.ToLower(strings.TrimSpace(req.Namespace))
	req.Key = strings.ToLower(strings.TrimSpace(req.Key))
	req.Label = strings.TrimSpace(req.Label)
	if req.Namespace == "" || req.Key == "" || req.Label == "" {
		writeJSONError(w, http.StatusBadRequest, "namespace, key and label are required")
		return
	}
	if !validNamespaceKey(req.Namespace) || !validNamespaceKey(req.Key) {
		writeJSONError(w, http.StatusBadRequest, "namespace and key must be lowercase letters, digits, '_' or '-'")
		return
	}
	module := &admin.Module{
		Namespace: req.Namespace,
		Key:       req.Key,
		Label:     req.Label,
		Hint:      strings.TrimSpace(req.Hint),
		SortOrder: req.SortOrder,
	}
	if err := a.Admin.CreateModule(module); err != nil {
		if admin.IsUniqueViolation(err) {
			writeJSONError(w, http.StatusConflict,
				fmt.Sprintf("module %s:%s already exists", req.Namespace, req.Key))
			return
		}
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.auditAPI(r, actor, "module.created", "", map[string]interface{}{
		"namespace": module.Namespace, "key": module.Key, "label": module.Label,
	})
	writeJSON(w, http.StatusCreated, map[string]interface{}{"module": module})
}

type updateModuleRequest struct {
	Label     string `json:"label"`
	Hint      string `json:"hint"`
	SortOrder int    `json:"sort_order"`
}

func (a *api) apiModuleUpdate(w http.ResponseWriter, r *http.Request, actor *users.User) {
	var req updateModuleRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Label = strings.TrimSpace(req.Label)
	if req.Label == "" {
		writeJSONError(w, http.StatusBadRequest, "label is required")
		return
	}
	id := r.PathValue("id")
	if err := a.Admin.UpdateModule(id, req.Label, strings.TrimSpace(req.Hint), req.SortOrder); err != nil {
		writeJSONError(w, mapRepoStatus(err), err.Error())
		return
	}
	a.auditAPI(r, actor, "module.updated", "", map[string]interface{}{
		"id": id, "label": req.Label,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (a *api) apiModuleRemove(w http.ResponseWriter, r *http.Request, actor *users.User) {
	id := r.PathValue("id")
	modules, _ := a.Admin.ListModules()
	var removed *admin.Module
	for i := range modules {
		if modules[i].ID == id {
			removed = &modules[i]
			break
		}
	}
	if err := a.Admin.DeleteModule(id); err != nil {
		writeJSONError(w, mapRepoStatus(err), err.Error())
		return
	}
	details := map[string]interface{}{"id": id}
	if removed != nil {
		details["namespace"] = removed.Namespace
		details["key"] = removed.Key
	}
	a.auditAPI(r, actor, "module.removed", "", details)
	writeJSON(w, http.StatusOK, map[string]string{"status": "removed"})
}

func validNamespaceKey(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

func mapRepoStatus(err error) int {
	if err == admin.ErrNotFound {
		return http.StatusNotFound
	}
	return http.StatusInternalServerError
}

// ── People ──

func (a *api) apiUserList(w http.ResponseWriter, r *http.Request, actor *users.User) {
	list, err := a.Users.List(strings.TrimSpace(r.URL.Query().Get("q")), 200)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"users": list})
}

type activeRequest struct {
	Active bool `json:"active"`
}

func (a *api) apiUserSetActive(w http.ResponseWriter, r *http.Request, actor *users.User) {
	id := r.PathValue("id")
	target, err := a.Users.GetByID(id)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "user not found")
		return
	}
	if target.ID == actor.ID {
		writeJSONError(w, http.StatusConflict, "you cannot deactivate your own account")
		return
	}
	var req activeRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.Users.SetActive(target.ID, req.Active); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	kind := "user.deactivated"
	if req.Active {
		kind = "user.activated"
	}
	a.auditAPI(r, actor, kind, "", map[string]interface{}{"email": target.Email})
	writeJSON(w, http.StatusOK, map[string]bool{"is_active": req.Active})
}

// ── Audit ──

func (a *api) apiAuditList(w http.ResponseWriter, r *http.Request, actor *users.User) {
	events, err := a.Admin.ListAuditEvents(strings.TrimSpace(r.URL.Query().Get("org_id")), 200)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"events": events})
}

// ── small helpers ──

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func firstNonEmptySlice(a, b []string) []string {
	if len(a) > 0 {
		return a
	}
	return b
}

func uuidNewString() string {
	return uuid.New().String()
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if net.ParseIP(host) == nil {
		return ""
	}
	return host
}

func firstWord(s string) string {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func lastWord(s string) string {
	fields := strings.Fields(s)
	if len(fields) < 2 {
		return ""
	}
	return fields[len(fields)-1]
}
