package db

import (
	"database/sql"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

const (
	defaultMaxOpenConns    = 10
	defaultMaxIdleConns    = 10
	defaultConnMaxLifetime = 30 * time.Minute
	defaultConnMaxIdleTime = 30 * time.Minute
)

func Open(dsn string) (*sql.DB, error) {
	conn, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}

	conn.SetMaxOpenConns(defaultMaxOpenConns)
	conn.SetMaxIdleConns(defaultMaxIdleConns)
	conn.SetConnMaxLifetime(defaultConnMaxLifetime)
	conn.SetConnMaxIdleTime(defaultConnMaxIdleTime)

	if err := conn.Ping(); err != nil {
		_ = conn.Close()
		return nil, err
	}

	return conn, nil
}
