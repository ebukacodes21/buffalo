package service

import "time"

type Discovery struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	JwksURI                           string   `json:"jwks_uri"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
}

type Token struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	IDToken      string `json:"id_token"`
}

type Jwks struct {
	Keys []JwksKey `json:"keys"`
}

type JwksKey struct {
	N   string `json:"n"`
	E   string `json:"e"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Kty string `json:"kty"`
}

type Organization struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Slug           string    `json:"slug"`
	Status         string    `json:"status"`
	ProductID      string    `json:"product_id"`
	ProductName    string    `json:"product_name"`
	RCNumber       string    `json:"rc_number"`
	Sector         string    `json:"sector"`
	AllocatedSeats int32     `json:"allocated_seats"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type Member struct {
	ID                string    `json:"id"`
	OrgID             string    `json:"org_id"`
	Role              string    `json:"role"`
	IsActive          bool      `json:"is_active"`
	Email             string    `json:"email"`
	EmailVerified     bool      `json:"email_verified"`
	PasswordHash      string    `json:"password_hash"`
	Name              string    `db:"name" json:"name"`
	GivenName         string    `json:"given_name"`
	FamilyName        string    `son:"family_name"`
	Picture           string    `json:"picture"`
	PreferredUsername string    `json:"preferred_username"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type User struct {
	Sub               string    `json:"sub"`
	ID                string    `json:"id"`
	IsPlatformAdmin   bool      `json:"is_platform_admin"`
	IsActive          bool      `json:"is_active"`
	Email             string    `json:"email"`
	EmailVerified     bool      `json:"email_verified"`
	PasswordHash      string    `json:"password_hash"`
	Name              string    `db:"name" json:"name"`
	GivenName         string    `json:"given_name"`
	FamilyName        string    `son:"family_name"`
	Picture           string    `json:"picture"`
	PreferredUsername string    `json:"preferred_username"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
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

type UserRow struct {
	ID              string    `json:"id"`
	Email           string    `json:"email"`
	Name            string    `json:"name"`
	EmailVerified   bool      `json:"email_verified"`
	IsActive        bool      `json:"is_active"`
	IsPlatformAdmin bool      `json:"is_platform_admin"`
	CreatedAt       time.Time `json:"created_at"`
}

type OnboardInput struct {
	OrgName        string `json:"name"`
	ProductID      string `json:"product_id"`
	ProductName    string `json:"product_name"`
	Slug           string `json:"slug"`
	OwnerName      string `json:"owner_name"`
	OwnerEmail     string `json:"owner_email"`
	OwnerPassword  string `json:"owner_password"`
	Sector         string `json:"sector"`
	AllocatedSeats int    `json:"allocated_seats"`
	RCNumber       string `json:"rc_number"`
}

type OnboardResult struct {
	Org    Organization `json:"organization"`
	Member Member       `json:"owner_membership"`
}

type OrgListing struct {
	Organization
	MemberCount int `json:"member_count"`
}

type MemberListing struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"org_id"`
	Role      string    `json:"role"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
}

type OauthClient struct {
	ID            string    `json:"id"`
	ClientID      string    `json:"client_id"`
	ClientSecret  string    `json:"client_secret"`
	BaseUrl       string    `json:"base_url"`
	Name          string    `json:"name"`
	RedirectUris  []string  `json:"redirect_uris"`
	GrantTypes    []string  `json:"grant_types"`
	ResponseTypes []string  `json:"response_types"`
	IsActive      bool      `json:"is_active"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type AccountRecord struct {
	Sub         string `json:"sub"`
	ID          string `json:"id"`
	Email       string `json:"email"`
	IsActive    bool   `json:"is_active"`
	Name        string `json:"name"`
	Role        string `json:"role"`
	Password    string `json:"password"`
	SubjectType string `json:"subject_type"`
}
