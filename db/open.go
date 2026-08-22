package db

import (
	"database/sql"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

const (
	defaultMaxOpenConns    = 10
	defaultMaxIdleConns    = 10
	defaultConnMaxLifetime = 30 * time.Minute
	defaultConnMaxIdleTime = 30 * time.Minute
)

// poolerSafe pins pgx to simple protocol unless the caller chose a mode.
// Transaction-pooling proxies (Supabase PgBouncer :6543) reassign backend
// connections between transactions, which corrupts pgx's cached *named*
// prepared statements and fails with SQLSTATE 42P05 / "does not exist".
func poolerSafe(dsn string) string {
	if strings.Contains(dsn, "default_query_exec_mode=") {
		return dsn
	}
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + "default_query_exec_mode=simple_protocol"
}

func Open(dsn string) (*sql.DB, error) {
	conn, err := sql.Open("pgx", poolerSafe(dsn))
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
