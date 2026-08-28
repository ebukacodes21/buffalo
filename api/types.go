package api

import (
	"time"

	"github.com/ebukacodes21/buffalo/service"
)

// Config holds the settings buffalo cannot derive at runtime. OAuth clients
// are no longer configured here — they live in the database and are managed
// through the Arkad Business Console.
type Config struct {
	Url string // public issuer URL, e.g. https://id.arkad.africa
}

// AppConfig is the resolved view of an oauth_clients row used inside the
// authorize/token flows.
type AppConfig struct {
	ClientID     string
	ClientSecret string
	Issuer       string
	RedirectURIs []string
}

type Payload struct {
	ClientID     string
	RedirectURI  string
	ResponseType string
	State        string
	Scope        string
	CodeIssuedAt time.Time
	// SubjectType is "user" for a platform admin (console) or "member" for a
	// business member (product app). It determines which table SubjectID and
	// the User/Member struct below reference.
	SubjectType string
	Record      *service.AccountRecord
	AppConfig   AppConfig
	// PKCE (RFC 7636): public clients (mobile apps) bind the authorization
	// code to a verifier instead of a client secret. Empty for confidential
	// clients, which keep authenticating with client_secret.
	CodeChallenge       string
	CodeChallengeMethod string
	// Organizations carries each org the member belongs to (role + paid
	// entitlements) so products can gate features without extra round trips.
	// Empty for platform admins.
	Organization *service.Organization
}

// SubjectID returns the id of the resolved principal (admin or member).
func (p Payload) SubjectID() string {
	return p.Record.ID
}

// SubjectEmail returns the email of the resolved principal.
func (p Payload) SubjectEmail() string {
	return p.Record.Email
}

// SubjectName returns the display name of the resolved principal.
func (p Payload) SubjectName() string {
	return p.Record.Name
}

// SubjectRoles returns the roles for the resolved principal. Platform admins
// are not org members and carry platform as role.
func (p Payload) SubjectRoles() []string {
	if p.Record != nil && p.Record.Role != "" {
		return []string{p.Record.Role}
	}
	return nil
}

// IsActive reports whether the resolved principal account is active.
func (p Payload) IsActive() bool {
	return p.Record.IsActive
}
