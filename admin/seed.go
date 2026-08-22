package admin

import (
	"database/sql"
	"log"
	"os"
)

// SeedDefaultClients ensures the platform's own first-party OAuth clients
// exist in the database. This replaces the old settings.yaml bootstrap: the
// console (and any future first-party product) is seeded by default, and
// everything else — TerraSell, TerraBooks, customer deployments — is managed
// through the Arkad Business Console UI.
//
// Values can be overridden per environment:
//
//	CONSOLE_CLIENT_ID / CONSOLE_CLIENT_SECRET / CONSOLE_REDIRECT_URI
func SeedDefaultClients(db *sql.DB) error {
	seeds := []Client{
		{
			ClientID:     envOr("CONSOLE_CLIENT_ID", "hyryriuehhjj222"),
			ClientSecret: envOr("CONSOLE_CLIENT_SECRET", "EJHW84Y9U920HEKABDJVBJDGUW4YU492GHEDJB2EUYR392"),
			Name:         "Arkad Business Console",
			RedirectURIs: []string{envOr("CONSOLE_REDIRECT_URI", "http://localhost:8090/oidc/callback")},
		},
	}

	for _, c := range seeds {
		var exists bool
		if err := db.QueryRow(
			`SELECT EXISTS (SELECT 1 FROM oauth_clients WHERE client_id = $1)`, c.ClientID,
		).Scan(&exists); err != nil {
			return err
		}
		if exists {
			continue
		}
		if _, err := db.Exec(`
			INSERT INTO oauth_clients (client_id, client_secret, name, redirect_uris)
			VALUES ($1, $2, $3, $4)
		`, c.ClientID, c.ClientSecret, c.Name, c.RedirectURIs); err != nil {
			return err
		}
		log.Printf("seeded default OAuth client %q (%s)", c.Name, c.ClientID)
	}
	return nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
