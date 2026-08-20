package main

import (
	"buffalo/api"
	"buffalo/db"
	"buffalo/tooling"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
)

var configFile = "config.yaml"

func main() {
	var (
		privateKey []byte
		err        error
	)

	if _, err = os.Stat(configFile); errors.Is(err, os.ErrNotExist) {
		fmt.Printf("error %s does not exist", configFile)
		os.Exit(1)
	}

	config, err := os.ReadFile(configFile)
	if err != nil {
		log.Fatalf("failed to load %s, err: %v", configFile, err)
	}

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
		dbURL = "postgres://postgres:postgres@localhost:5432/buffalo?sslmode=disable"
	}

	if err := db.RunMigrations(dbURL); err != nil {
		log.Fatalf("failed to run migrations: %v", err)
	}

	database, err := db.Open(dbURL)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	defer database.Close()

	fmt.Printf("api stopped: %s", api.Start(&http.Server{Addr: ":8089"}, privateKey, api.ReadConfig(config), database))
}
