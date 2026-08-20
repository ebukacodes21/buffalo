package db

import (
	"embed"
	"fmt"
	"io/fs"
	"log"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

func RunMigrations(migrationURL string) error {
	d, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("create iofs driver: %w", err)
	}

	m, err := migrate.NewWithSourceInstance("iofs", d, migrationURL)
	if err != nil {
		return fmt.Errorf("start migration instance: %w", err)
	}
	defer m.Close()

	version, dirty, err := m.Version()
	if err != nil && err != migrate.ErrNilVersion {
		log.Printf("could not get migration version: %v", err)
	}

	if dirty {
		log.Printf("database is dirty at version %d, forcing...", version)
		if err := m.Force(int(version)); err != nil {
			return fmt.Errorf("force migration version: %w", err)
		}
	}

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("migration up: %w", err)
	}

	log.Println("migration completed successfully")
	return nil
}

func init() {
	if _, err := fs.ReadDir(migrationsFS, "migrations"); err != nil {
		panic(fmt.Sprintf("embed migrations: %v", err))
	}
}
