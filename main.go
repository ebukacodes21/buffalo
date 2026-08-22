package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/ebukacodes21/buffalo/admin"
	"github.com/ebukacodes21/buffalo/api"
	"github.com/ebukacodes21/buffalo/db"
	"github.com/ebukacodes21/buffalo/tooling"

	"github.com/joho/godotenv"
)

// issuerURL resolves the public URL of this buffalo instance. OAuth clients
// are seeded into the database — settings.yaml is gone.
func issuerURL() string {
	if v := os.Getenv("BUFFALO_URL"); v != "" {
		return v
	}
	return "http://localhost:8089"
}

func main() {
	// .env is a local-dev convenience; platforms like Render inject real env
	// vars and this becomes a no-op.
	_ = godotenv.Load()

	var (
		privateKey []byte
		err        error
	)

	if _, err = os.Stat("enckey.pem"); errors.Is(err, os.ErrNotExist) {
		if privateKey, _, err = tooling.GenerateKeys(); err != nil {
			fmt.Printf("error: %s\n", err)
			os.Exit(1)
		}
		if err = os.WriteFile("enckey.pem", privateKey, 0600); err != nil {
			fmt.Printf("error: %s\n", err)
			os.Exit(1)
		}
	} else {
		privateKey, err = os.ReadFile("enckey.pem")
		if err != nil {
			log.Fatalf("failed to load enckey.pem, err: %v", err)
		}
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatalf("missing database key, err: %v", err)
	}

	if err := db.RunMigrations(dbURL); err != nil {
		log.Fatalf("failed to run migrations: %v", err)
	}

	database, err := db.Open(dbURL)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	defer database.Close()

	if err := admin.SeedDefaultClients(database); err != nil {
		log.Fatalf("failed to seed default clients: %v", err)
	}

	fmt.Printf("api stopped: %s", api.Start(&http.Server{Addr: ":8089"}, privateKey, api.Config{Url: issuerURL()}, database))
}
