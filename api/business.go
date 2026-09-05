package api

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/ebukacodes21/buffalo/service"
	"github.com/ebukacodes21/buffalo/tooling"
)

// ── Stats ──

func (a *api) apiStats(w http.ResponseWriter, r *http.Request, actor *service.User) {
	stats, err := a.Svc.Stats(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	events, err := a.Svc.ListAuditEvents(r.Context(), "", 10)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"stats":        stats,
		"recent_audit": events,
	})
}

// ── Businesses ──

func (a *api) apiBusinessList(w http.ResponseWriter, r *http.Request, actor *service.User) {
	orgs, err := a.Svc.ListOrgs(r.Context(), strings.TrimSpace(r.URL.Query().Get("q")), 200)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"businesses": orgs})
}

func (a *api) apiBusinessOnboard(w http.ResponseWriter, r *http.Request, actor *service.User) {
	var req service.OnboardInput
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	req.OrgName = strings.TrimSpace(req.OrgName)
	req.AdminEmail = strings.ToLower(strings.TrimSpace(req.AdminEmail))
	req.AdminName = strings.TrimSpace(req.AdminName)

	adminRole := strings.TrimSpace(req.AdminRole)
	if adminRole == "" {
		adminRole = "admin"
	}
	if adminRole != "owner" && adminRole != "admin" && adminRole != "member" {
		writeJSONError(w, http.StatusBadRequest, "admin_role must be owner, admin or member")
		return
	}
	req.AdminRole = adminRole

	if req.OrgName == "" || req.AdminEmail == "" || req.AdminName == "" {
		writeJSONError(w, http.StatusBadRequest, "name, admin_name and admin_email are required")
		return
	}
	if !safeText(req.OrgName) || hasScriptMarker(req.OrgName) {
		writeJSONError(w, http.StatusBadRequest, "organization name contains characters that aren't allowed")
		return
	}
	if !lettersOnly(req.AdminName) || hasScriptMarker(req.AdminName) {
		writeJSONError(w, http.StatusBadRequest, "admin_name may only contain letters, spaces and . ' - & ( )")
		return
	}
	if !validEmail(req.AdminEmail) {
		writeJSONError(w, http.StatusBadRequest, "admin_email is not a valid email address")
		return
	}
	if req.Slug != "" && !validSlug(req.Slug) {
		writeJSONError(w, http.StatusBadRequest, "slug may only contain lowercase letters, digits and dashes")
		return
	}

	password := req.AdminPassword
	generated := false
	if password == "" {
		var err error
		if password, err = tooling.GetRandomString(14); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "could not generate admin password")
			return
		}
		generated = true
	} else if len(password) < 8 {
		writeJSONError(w, http.StatusBadRequest, "admin_password must be at least 8 characters")
		return
	}

	slug := req.Slug
	if slug == "" {
		slug = tooling.Slugify(firstNonEmpty(req.Slug, req.OrgName))
	}

	result, err := a.Svc.OnboardBusiness(r.Context(), req)
	if err == tooling.ErrSlugTaken {
		writeJSONError(w, http.StatusConflict, fmt.Sprintf("slug %q is already taken", slug))
		return
	}
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	a.auditAPI(r, actor, "org.created", result.Org.ID, map[string]interface{}{
		"name": result.Org.Name, "slug": result.Org.Slug, "admin": req.AdminEmail,
	})

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"organization":       result.Org,
		"admin_membership":   result.Member,
		"admin_credentials": map[string]interface{}{
			"email":     req.AdminEmail,
			"password":  password,
			"generated": generated,
		},
	})
}

type businessDetail struct {
	Organization *service.Organization   `json:"organization"`
	Entitlements []string                `json:"entitlements"`
	Members      []service.MemberListing `json:"members"`
	Audit        []service.AuditEvent    `json:"audit"`
}

func (a *api) apiBusinessDetail(w http.ResponseWriter, r *http.Request, actor *service.User) {
	org, ok := a.loadOrgOr404(w, r)
	if !ok {
		return
	}
	entitlements, _ := a.Svc.ListEntitlements(r.Context(), org.ID)
	members, _ := a.Svc.ListMembers(r.Context(), org.ID)
	events, _ := a.Svc.ListAuditEvents(r.Context(), org.ID, 20)

	writeJSON(w, http.StatusOK, businessDetail{
		Organization: org, Entitlements: entitlements, Members: members, Audit: events,
	})
}

type entitlementsRequest struct {
	Entitlements []string `json:"entitlements"`
}

var entitlementRe = regexp.MustCompile(`^[a-z0-9][a-z0-9:_-]{0,99}$`)

func normalizeEntitlements(items []string) ([]string, error) {
	seen := make(map[string]bool, len(items))
	out := make([]string, 0, len(items))
	for _, raw := range items {
		key := strings.ToLower(strings.TrimSpace(raw))
		if key == "" {
			continue
		}
		if !entitlementRe.MatchString(key) {
			return nil, fmt.Errorf("invalid entitlement key %q (use lowercase letters, digits, ':', '_' or '-')", raw)
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, key)
	}
	if len(out) > 100 {
		return nil, fmt.Errorf("too many entitlements (max 100)")
	}
	return out, nil
}

// apiBusinessEntitlements replaces the paid entitlement set for a business.
// The console sends the complete desired list; products observe the change
// via token claims / userinfo and gate their features accordingly.
func (a *api) apiBusinessEntitlements(w http.ResponseWriter, r *http.Request, actor *service.User) {
	org, ok := a.loadOrgOr404(w, r)
	if !ok {
		return
	}
	var req entitlementsRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	items, err := normalizeEntitlements(req.Entitlements)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	before, err := a.Svc.ListEntitlements(r.Context(), org.ID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := a.Svc.SetEntitlements(r.Context(), org.ID, items); err != nil {
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

func (a *api) apiBusinessStatus(w http.ResponseWriter, r *http.Request, actor *service.User) {
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
	if err := a.Svc.SetOrgStatus(r.Context(), org.ID, req.Status); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.auditAPI(r, actor, "org.status_changed", org.ID, map[string]interface{}{
		"from": org.Status, "to": req.Status,
	})
	org.Status = req.Status
	writeJSON(w, http.StatusOK, map[string]interface{}{"organization": org})
}
