package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/ebukacodes21/buffalo/db"
	"github.com/ebukacodes21/buffalo/users"

	"github.com/google/uuid"
)

func main() {
	email := flag.String("email", "", "User email (required)")
	password := flag.String("password", "", "User password (required)")
	name := flag.String("name", "", "Full name (required)")
	givenName := flag.String("given-name", "", "Given name")
	familyName := flag.String("family-name", "", "Family name")
	platformAdmin := flag.Bool("platform-admin", false, "Grant platform admin (console) access")
	flag.Parse()

	if *email == "" || *password == "" || *name == "" {
		fmt.Println("Usage: seed -email <email> -password <password> -name <name> [-given-name <name>] [-family-name <name>]")
		os.Exit(1)
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://postgres:postgres@localhost:5432/buffalo?sslmode=disable"
	}

	database, err := db.Open(dbURL)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	defer database.Close()

	repo := users.NewRepository(database)

	hash, err := users.HashPassword(*password)
	if err != nil {
		log.Fatalf("failed to hash password: %v", err)
	}

	user := &users.User{
		ID:                uuid.New().String(),
		Email:             *email,
		EmailVerified:     true,
		PasswordHash:      hash,
		Name:              *name,
		GivenName:         *givenName,
		FamilyName:        *familyName,
		PreferredUsername: *email,
		IsActive:          true,
		IsPlatformAdmin:   *platformAdmin,
	}

	if err := repo.Create(user); err != nil {
		log.Fatalf("failed to create user: %v", err)
	}

	fmt.Printf("User created successfully: %s (%s)\n", user.Name, user.Email)
}
