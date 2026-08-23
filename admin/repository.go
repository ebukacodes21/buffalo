package admin

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/ebukacodes21/buffalo/tooling"
	"github.com/ebukacodes21/buffalo/users"

	"github.com/google/uuid"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrSlugTaken     = errors.New("an organization with that slug already exists")
	ErrEmailInUse    = errors.New("a user with that email already exists")
	ErrAlreadyMember = errors.New("user is already a member of this organization")
)

type Organization struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Member struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"org_id"`
	UserID    string    `json:"user_id"`
	Role      string    `json:"role"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
}

type Client struct {
	ID           string    `json:"id"`
	ClientID     string    `json:"client_id"`
	ClientSecret string    `json:"client_secret,omitempty"`
	SecretOnce   string    `json:"secret_once,omitempty"`
	Name         string    `json:"name"`
	RedirectURIs []string  `json:"redirect_uris"`
	IsActive     bool      `json:"is_active"`
	CreatedAt    time.Time `json:"created_at"`
}

type AuditEvent struct {
	ID        string                 `json:"id"`
	UserName  string                 `json:"user_name,omitempty"`
	OrgName   string                 `json:"org_name,omitempty"`
	EventType string                 `json:"event_type"`
	Details   map[string]interface{} `json:"details,omitempty"`
	CreatedAt time.Time              `json:"created_at"`
}

type Stats struct {
	Organizations int `json:"organizations"`
	ActiveOrgs    int `json:"active_organizations"`
	Users         int `json:"users"`
	Apps          int `json:"applications"`
	ActiveApps    int `json:"active_applications"`
}

type OnboardInput struct {
	OrgName       string `json:"name"`
	Slug          string `json:"slug"`
	OwnerName     string `json:"owner_name"`
	OwnerEmail    string `json:"owner_email"`
	OwnerPassword string `json:"owner_password"`
}

type OnboardResult struct {
	Org    Organization `json:"organization"`
	Member Member       `json:"owner_membership"`
}

type Repository struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

func scanOrg(row interface{ Scan(...any) error }) (*Organization, error) {
	o := &Organization{}
	err := row.Scan(&o.ID, &o.Name, &o.Slug, &o.Status, &o.CreatedAt, &o.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return o, nil
}

const orgColumns = `id, name, slug, status, created_at, updated_at`

// ── Organizations ──

func (r *Repository) CreateOrgTx(tx *sql.Tx, name, slug string) (*Organization, error) {
	o := &Organization{Name: name, Slug: slug, Status: "active"}
	err := tx.QueryRow(`
		INSERT INTO organizations (name, slug) VALUES ($1, $2)
		RETURNING id, name, slug, status, created_at, updated_at
	`, name, slug).Scan(&o.ID, &o.Name, &o.Slug, &o.Status, &o.CreatedAt, &o.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return o, nil
}

func (r *Repository) GetOrg(id string) (*Organization, error) {
	return scanOrg(r.db.QueryRow(`SELECT `+orgColumns+` FROM organizations WHERE id = $1`, id))
}

func (r *Repository) GetOrgBySlug(slug string) (*Organization, error) {
	return scanOrg(r.db.QueryRow(`SELECT `+orgColumns+` FROM organizations WHERE slug = $1`, slug))
}

type OrgRow struct {
	Organization
	MemberCount int `json:"member_count"`
}

func (r *Repository) ListOrgs(search string, limit int) ([]OrgRow, error) {
	pattern := "%" + search + "%"
	rows, err := r.db.Query(`
		SELECT o.id, o.name, o.slug, o.status, o.created_at, o.updated_at,
		       (SELECT COUNT(*) FROM org_members m WHERE m.org_id = o.id)
		FROM organizations o
		WHERE ($1 = '' OR o.name ILIKE $2 OR o.slug ILIKE $2)
		ORDER BY o.created_at DESC
		LIMIT $3
	`, search, pattern, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []OrgRow{}
	for rows.Next() {
		var row OrgRow
		if err := rows.Scan(&row.ID, &row.Name, &row.Slug, &row.Status, &row.CreatedAt, &row.UpdatedAt,
			&row.MemberCount); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func (r *Repository) SetOrgStatus(id, status string) error {
	res, err := r.db.Exec(`UPDATE organizations SET status = $2, updated_at = NOW() WHERE id = $1`, id, status)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *Repository) RenameOrg(id, name string) error {
	res, err := r.db.Exec(`UPDATE organizations SET name = $2, updated_at = NOW() WHERE id = $1`, id, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ── Members ──

const memberColumns = `
	m.id, m.org_id, m.user_id, m.role, u.name, u.email, u.is_active, m.created_at`

func scanMember(row interface{ Scan(...any) error }) (*Member, error) {
	m := &Member{}
	err := row.Scan(&m.ID, &m.OrgID, &m.UserID, &m.Role, &m.Name, &m.Email, &m.IsActive, &m.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return m, nil
}

func (r *Repository) AddMemberTx(tx *sql.Tx, orgID, userID, role string) (*Member, error) {
	m := &Member{}
	err := tx.QueryRow(`
		INSERT INTO org_members (org_id, user_id, role) VALUES ($1, $2, $3)
		RETURNING id, org_id, user_id, role, '', '', true, created_at
	`, orgID, userID, role).Scan(&m.ID, &m.OrgID, &m.UserID, &m.Role, &m.Name, &m.Email, &m.IsActive, &m.CreatedAt)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func (r *Repository) GetMember(orgID, memberID string) (*Member, error) {
	return scanMember(r.db.QueryRow(`
		SELECT `+memberColumns+`
		FROM org_members m JOIN users u ON u.id = m.user_id
		WHERE m.org_id = $1 AND m.id = $2
	`, orgID, memberID))
}

func (r *Repository) ListMembers(orgID string) ([]Member, error) {
	rows, err := r.db.Query(`
		SELECT `+memberColumns+`
		FROM org_members m JOIN users u ON u.id = m.user_id
		WHERE m.org_id = $1
		ORDER BY CASE m.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END, m.created_at
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Member{}
	for rows.Next() {
		var m Member
		if err := rows.Scan(&m.ID, &m.OrgID, &m.UserID, &m.Role, &m.Name, &m.Email, &m.IsActive, &m.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (r *Repository) AddMember(orgID, userID, role string) error {
	_, err := r.db.Exec(`INSERT INTO org_members (org_id, user_id, role) VALUES ($1, $2, $3)`, orgID, userID, role)
	if err != nil && isUniqueViolation(err) {
		return ErrAlreadyMember
	}
	return err
}

func (r *Repository) CountOwners(orgID string) (int, error) {
	var count int
	err := r.db.QueryRow(`SELECT COUNT(*) FROM org_members WHERE org_id = $1 AND role = 'owner'`, orgID).Scan(&count)
	return count, err
}

func (r *Repository) UpdateMemberRole(orgID, memberID, role string) error {
	res, err := r.db.Exec(`UPDATE org_members SET role = $3 WHERE org_id = $1 AND id = $2`, orgID, memberID, role)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *Repository) RemoveMember(orgID, memberID string) error {
	res, err := r.db.Exec(`DELETE FROM org_members WHERE org_id = $1 AND id = $2`, orgID, memberID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ── OAuth Clients ──

const clientColumns = `id, client_id, client_secret, name, redirect_uris, is_active, created_at`

// textArray converts a Postgres TEXT[] value as delivered by the pgx
// stdlib driver ([]string or "{a,b}" literal) into a []string.
func textArray(v any) []string {
	switch t := v.(type) {
	case nil:
		return nil
	case []string:
		return t
	case []byte:
		return parseTextArrayLiteral(string(t))
	case string:
		return parseTextArrayLiteral(t)
	default:
		return nil
	}
}

func parseTextArrayLiteral(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" || s == "{}" {
		return []string{}
	}
	s = strings.TrimPrefix(s, "{")
	s = strings.TrimSuffix(s, "}")
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(p, `"`) && strings.HasSuffix(p, `"`) && len(p) >= 2 {
			p = p[1 : len(p)-1]
			p = strings.ReplaceAll(p, `\"`, `"`)
			p = strings.ReplaceAll(p, `\\`, `\`)
		}
		out = append(out, p)
	}
	return out
}

func scanClient(row interface{ Scan(...any) error }) (*Client, error) {
	c := &Client{}
	var uris any
	err := row.Scan(&c.ID, &c.ClientID, &c.ClientSecret, &c.Name, &uris, &c.IsActive, &c.CreatedAt)
	c.RedirectURIs = textArray(uris)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if c.RedirectURIs == nil {
		c.RedirectURIs = []string{}
	}
	return c, nil
}

// GetActiveClientByClientID looks up an enabled OAuth client by its public
// client_id. This is what makes dynamically provisioned businesses work in
// the authorize/token flows without touching config.yaml.
func (r *Repository) GetActiveClientByClientID(clientID string) (*Client, error) {
	return scanClient(r.db.QueryRow(`
		SELECT `+clientColumns+` FROM oauth_clients WHERE client_id = $1 AND is_active
	`, clientID))
}

func (r *Repository) GetClient(id string) (*Client, error) {
	return scanClient(r.db.QueryRow(`SELECT `+clientColumns+` FROM oauth_clients WHERE id = $1`, id))
}

type ClientRow struct {
	Client
}

func (r *Repository) ListClients(search string, limit int) ([]ClientRow, error) {
	pattern := "%" + search + "%"
	rows, err := r.db.Query(`
		SELECT `+clientColumns+`
		FROM oauth_clients
		WHERE ($1 = '' OR name ILIKE $2 OR client_id ILIKE $2)
		ORDER BY created_at DESC
		LIMIT $3
	`, search, pattern, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []ClientRow{}
	for rows.Next() {
		var row ClientRow
		var uris any
		if err := rows.Scan(&row.ID, &row.ClientID, &row.ClientSecret, &row.Name,
			&uris, &row.IsActive, &row.CreatedAt); err != nil {
			return nil, err
		}
		row.RedirectURIs = textArray(uris)
		out = append(out, row)
	}
	return out, rows.Err()
}

func (r *Repository) UpdateClient(id, name string, redirectURIs []string, isActive bool) error {
	res, err := r.db.Exec(`
		UPDATE oauth_clients SET name = $2, redirect_uris = $3, is_active = $4, updated_at = NOW() WHERE id = $1
	`, id, name, redirectURIs, isActive)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *Repository) CreateClient(c *Client) error {
	return r.db.QueryRow(`
		INSERT INTO oauth_clients (client_id, client_secret, name, redirect_uris)
		VALUES ($1, $2, $3, $4)
		RETURNING id, is_active, created_at
	`, c.ClientID, c.ClientSecret, c.Name, c.RedirectURIs).
		Scan(&c.ID, &c.IsActive, &c.CreatedAt)
}

func (r *Repository) RotateClientSecret(id, secret string) error {
	res, err := r.db.Exec(`UPDATE oauth_clients SET client_secret = $2, updated_at = NOW() WHERE id = $1`, id, secret)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ── Entitlements ──

// OrgMembership is a user's membership in one organization together with
// everything that organization is entitled to. It is what tokens and
// userinfo expose so products can gate features on what was paid for.
type OrgMembership struct {
	OrgID        string   `json:"org_id"`
	Slug         string   `json:"slug"`
	Name         string   `json:"name"`
	Role         string   `json:"role"`
	Entitlements []string `json:"entitlements"`
}

var entitlementRe = regexp.MustCompile(`^[a-z0-9][a-z0-9:_-]{0,99}$`)

// NormalizeEntitlements validates and dedupes entitlement keys. Keys are
// namespaced per product, "<namespace>:<feature>", e.g. "acme:invoicing".
func NormalizeEntitlements(items []string) ([]string, error) {
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

func (r *Repository) ListEntitlements(orgID string) ([]string, error) {
	rows, err := r.db.Query(`
		SELECT entitlement FROM org_entitlements WHERE org_id = $1 ORDER BY entitlement
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []string{}
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, err
		}
		out = append(out, key)
	}
	return out, rows.Err()
}

// SetEntitlements replaces the full entitlement set for an organization in
// one transaction. The console always sends the complete desired list.
func (r *Repository) SetEntitlements(orgID string, items []string) error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err = tx.Exec(`DELETE FROM org_entitlements WHERE org_id = $1`, orgID); err != nil {
		return err
	}
	for _, key := range items {
		if _, err = tx.Exec(`
			INSERT INTO org_entitlements (org_id, entitlement) VALUES ($1, $2)
			ON CONFLICT (org_id, entitlement) DO NOTHING
		`, orgID, key); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ListMembershipsForUser returns every organization the user belongs to,
// with their role in it and that org's entitlements.
func (r *Repository) ListMembershipsForUser(userID string) ([]OrgMembership, error) {
	rows, err := r.db.Query(`
		SELECT o.id, o.slug, o.name, m.role,
		       COALESCE((
		           SELECT array_agg(e.entitlement ORDER BY e.entitlement)
		           FROM org_entitlements e WHERE e.org_id = o.id
		       ), '{}')
		FROM org_members m
		JOIN organizations o ON o.id = m.org_id
		WHERE m.user_id = $1 AND o.status = 'active'
		ORDER BY o.created_at
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []OrgMembership{}
	for rows.Next() {
		var m OrgMembership
		var ent any
		if err := rows.Scan(&m.OrgID, &m.Slug, &m.Name, &m.Role, &ent); err != nil {
			return nil, err
		}
		m.Entitlements = textArray(ent)
		if m.Entitlements == nil {
			m.Entitlements = []string{}
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ── Product module catalog ──

// Module is one purchasable item of a product, e.g. terrasell/healthcare.
// The catalog is data managed through the console; entitlement keys stored
// on orgs are "<namespace>:<module_key>".
type Module struct {
	ID        string    `json:"id"`
	Namespace string    `json:"namespace"`
	Key       string    `json:"key"`
	Label     string    `json:"label"`
	Hint      string    `json:"hint"`
	SortOrder int       `json:"sort_order"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

const moduleColumns = `id, namespace, module_key, label, hint, sort_order, created_at, updated_at`

func (r *Repository) ListModules() ([]Module, error) {
	rows, err := r.db.Query(`
		SELECT ` + moduleColumns + ` FROM product_modules
		ORDER BY namespace, sort_order, label
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Module{}
	for rows.Next() {
		var m Module
		if err := rows.Scan(&m.ID, &m.Namespace, &m.Key, &m.Label, &m.Hint,
			&m.SortOrder, &m.CreatedAt, &m.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (r *Repository) CreateModule(m *Module) error {
	return r.db.QueryRow(`
		INSERT INTO product_modules (namespace, module_key, label, hint, sort_order)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, created_at, updated_at
	`, m.Namespace, m.Key, m.Label, m.Hint, m.SortOrder).
		Scan(&m.ID, &m.CreatedAt, &m.UpdatedAt)
}

func (r *Repository) UpdateModule(id string, label, hint string, sortOrder int) error {
	res, err := r.db.Exec(`
		UPDATE product_modules SET label = $2, hint = $3, sort_order = $4, updated_at = NOW() WHERE id = $1
	`, id, label, hint, sortOrder)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *Repository) DeleteModule(id string) error {
	res, err := r.db.Exec(`DELETE FROM product_modules WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ── Admin sessions ──

func (r *Repository) CreateAdminSession(userID, token string, expiresAt time.Time) error {
	_, err := r.db.Exec(`
		INSERT INTO admin_sessions (token, user_id, expires_at) VALUES ($1, $2, $3)
	`, token, userID, expiresAt)
	return err
}

func (r *Repository) GetAdminSession(token string) (*users.User, error) {
	u := &users.User{}
	err := r.db.QueryRow(`
		SELECT u.id, u.email, u.name, u.is_active, u.is_platform_admin
		FROM admin_sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token = $1 AND s.expires_at > NOW()
	`, token).Scan(&u.ID, &u.Email, &u.Name, &u.IsActive, &u.IsPlatformAdmin)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (r *Repository) DeleteAdminSession(token string) error {
	_, err := r.db.Exec(`DELETE FROM admin_sessions WHERE token = $1`, token)
	return err
}

func (r *Repository) PurgeExpiredSessions() error {
	_, err := r.db.Exec(`DELETE FROM admin_sessions WHERE expires_at < NOW()`)
	return err
}

// ── Audit log ──

func (r *Repository) InsertAuditEvent(userID, orgID, eventType string, details map[string]interface{}, ip, userAgent string) error {
	// Marshal to string (not []byte): pgx's simple-protocol mode (required
	// behind transaction poolers) would otherwise send []byte as a bytea
	// literal, which has no cast to the jsonb details column.
	var payload string
	if len(details) > 0 {
		b, err := json.Marshal(details)
		if err != nil {
			return fmt.Errorf("marshal audit details: %w", err)
		}
		payload = string(b)
	}
	_, err := r.db.Exec(`
		INSERT INTO audit_events (user_id, org_id, event_type, details, ip_address, user_agent)
		VALUES (NULLIF($1,'')::uuid, NULLIF($2,'')::uuid, $3, NULLIF($4,'')::jsonb, NULLIF($5,'')::inet, NULLIF($6,''))
	`, userID, orgID, eventType, payload, ip, userAgent)
	return err
}

func (r *Repository) ListAuditEvents(orgID string, limit int) ([]AuditEvent, error) {
	rows, err := r.db.Query(`
		SELECT e.id, COALESCE(u.name, ''), COALESCE(o.name, ''), e.event_type, e.details, e.created_at
		FROM audit_events e
		LEFT JOIN users u ON u.id = e.user_id
		LEFT JOIN organizations o ON o.id = e.org_id
		WHERE ($1 = '' OR e.org_id::text = $1)
		ORDER BY e.created_at DESC
		LIMIT $2
	`, orgID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []AuditEvent{}
	for rows.Next() {
		var e AuditEvent
		var raw []byte
		if err := rows.Scan(&e.ID, &e.UserName, &e.OrgName, &e.EventType, &raw, &e.CreatedAt); err != nil {
			return nil, err
		}
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &e.Details)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ── Dashboard ──

func (r *Repository) Stats() (Stats, error) {
	s := Stats{}
	err := r.db.QueryRow(`
		SELECT
			(SELECT COUNT(*) FROM organizations),
			(SELECT COUNT(*) FROM organizations WHERE status = 'active'),
			(SELECT COUNT(*) FROM users),
			(SELECT COUNT(*) FROM oauth_clients),
			(SELECT COUNT(*) FROM oauth_clients WHERE is_active)
	`).Scan(&s.Organizations, &s.ActiveOrgs, &s.Users, &s.Apps, &s.ActiveApps)
	return s, err
}

// ── Onboarding ──

// OnboardBusiness provisions everything a new business needs on buffalo in a
// single transaction: the organization, its owner account, and the owner's
// membership. OAuth clients are platform products and are managed
// independently of businesses.
func (r *Repository) OnboardBusiness(in OnboardInput) (*OnboardResult, error) {
	hash, err := users.HashPassword(in.OwnerPassword)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	tx, err := r.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	result := &OnboardResult{}

	org, err := r.CreateOrgTx(tx, in.OrgName, in.Slug)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, ErrSlugTaken
		}
		return nil, fmt.Errorf("create organization: %w", err)
	}
	result.Org = *org

	owner := &users.User{
		ID:                uuid.New().String(),
		Email:             strings.ToLower(strings.TrimSpace(in.OwnerEmail)),
		EmailVerified:     false,
		PasswordHash:      hash,
		Name:              in.OwnerName,
		GivenName:         ownerGivenName(in.OwnerName),
		FamilyName:        ownerFamilyName(in.OwnerName),
		PreferredUsername: strings.ToLower(strings.TrimSpace(in.OwnerEmail)),
		IsActive:          true,
	}

	existingID, err := findUserIDByEmail(tx, owner.Email)
	if err != nil && err != users.ErrUserNotFound {
		return nil, fmt.Errorf("lookup owner email: %w", err)
	}

	if existingID == "" {
		if err = createUserTx(tx, owner); err != nil {
			return nil, fmt.Errorf("create owner: %w", err)
		}
	} else {
		owner.ID = existingID
	}

	member, err := r.AddMemberTx(tx, org.ID, owner.ID, "owner")
	if err != nil {
		return nil, fmt.Errorf("add owner membership: %w", err)
	}
	member.Name, member.Email = owner.Name, owner.Email
	result.Member = *member

	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

func findUserIDByEmail(tx *sql.Tx, email string) (string, error) {
	var id string
	err := tx.QueryRow(`SELECT id FROM users WHERE email = $1`, email).Scan(&id)
	if err == sql.ErrNoRows {
		return "", users.ErrUserNotFound
	}
	return id, err
}

func createUserTx(tx *sql.Tx, u *users.User) error {
	_, err := tx.Exec(`
		INSERT INTO users (id, email, email_verified, password_hash, name, given_name, family_name, picture, preferred_username, is_active, is_platform_admin)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`, u.ID, u.Email, u.EmailVerified, u.PasswordHash, u.Name, u.GivenName, u.FamilyName,
		u.Picture, u.PreferredUsername, u.IsActive, u.IsPlatformAdmin)
	return err
}

// IsUniqueViolation reports whether err is a Postgres unique-constraint
// violation (SQLSTATE 23505).
func IsUniqueViolation(err error) bool {
	type coder interface{ SQLState() string }
	if c, ok := err.(coder); ok {
		return c.SQLState() == "23505"
	}
	return strings.Contains(err.Error(), "duplicate key")
}

func isUniqueViolation(err error) bool {
	return IsUniqueViolation(err)
}

var slugStrip = regexp.MustCompile(`[^a-z0-9]+`)

func Slugify(name string) string {
	slug := strings.Trim(slugStrip.ReplaceAllString(strings.ToLower(name), "-"), "-")
	if len(slug) > 100 {
		slug = slug[:100]
	}
	if slug == "" {
		slug = "business"
	}
	return slug
}

func ownerGivenName(name string) string {
	parts := strings.Fields(name)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

func ownerFamilyName(name string) string {
	parts := strings.Fields(name)
	if len(parts) < 2 {
		return ""
	}
	return parts[len(parts)-1]
}

// NewClientCredentials generates a fresh public client_id and secret pair
// for registering an OAuth application.
func NewClientCredentials() (clientID, clientSecret string, err error) {
	if clientID, err = randomToken("buf_", 12); err != nil {
		return "", "", err
	}
	if clientSecret, err = randomToken("", 48); err != nil {
		return "", "", err
	}
	return clientID, clientSecret, nil
}

func randomToken(prefix string, n int) (string, error) {
	s, err := tooling.GetRandomString(n)
	if err != nil {
		return "", err
	}
	return prefix + s, nil
}
