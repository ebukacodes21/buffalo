package db

import (
	"context"
	"database/sql"
)

type Repository struct {
	*Queries
	db *sql.DB
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db, Queries: New(db)}
}

func (r *Repository) ExecTx(ctx context.Context, fn func(tx *Queries) error) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	q := New(tx)
	err = fn(q)
	if err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return rbErr
		}
		return err
	}

	return tx.Commit()
}
