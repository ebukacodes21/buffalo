package api

import (
	"time"

	"github.com/ebukacodes21/buffalo/admin"
	"github.com/ebukacodes21/buffalo/users"
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
	User         users.User
	AppConfig    AppConfig
	// PKCE (RFC 7636): public clients (mobile apps) bind the authorization
	// code to a verifier instead of a client secret. Empty for confidential
	// clients, which keep authenticating with client_secret.
	CodeChallenge       string
	CodeChallengeMethod string
	// Organizations carries each org the user belongs to (role + paid
	// entitlements) so products can gate features without extra round trips.
	Organizations []admin.OrgMembership
}
