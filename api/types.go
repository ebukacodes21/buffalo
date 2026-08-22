package api

import (
	"time"

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
}
