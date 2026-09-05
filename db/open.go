package db

import (
	"database/sql"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// poolerSafe pins pgx to simple protocol unless the caller chose a mode.
// Transaction-pooling proxies (Supabase PgBouncer :6543) reassign backend
// connections between transactions, which corrupts pgx's cached *named*
// prepared statements and fails with SQLSTATE 42P05 / "does not exist".
func poolerSafe(dsn string) string {
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	if strings.Contains(dsn, "default_query_exec_mode=") {
		return dsn + sep + "connect_timeout=10"
	}
	return dsn + sep + "default_query_exec_mode=simple_protocol&connect_timeout=10"
}

func Open(dsn string) (*sql.DB, error) {
	conn, err := sql.Open("pgx", poolerSafe(dsn))
	if err != nil {
		return nil, err
	}

	// Keep the pool small and short-lived. The Supabase transaction pooler
	// reassigns backends, so long-lived connections outlive their sockets and
	// a request for a stale one can stall for minutes. A bounded connect
	// timeout turns that silent hang into a fast error instead.
	conn.SetMaxOpenConns(10)
	conn.SetMaxIdleConns(2)
	conn.SetConnMaxLifetime(10 * time.Minute)
	conn.SetConnMaxIdleTime(2 * time.Minute)

	if err := conn.Ping(); err != nil {
		_ = conn.Close()
		return nil, err
	}

	return conn, nil
}
