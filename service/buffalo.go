package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	repo "github.com/ebukacodes21/buffalo/db"
)

type Buffalo struct {
	repo *repo.Repository
}

func NewBuffalo(db *sql.DB) *Buffalo {
	return &Buffalo{
		repo: repo.NewRepository(db),
	}
}

// LookupEmail queries the users table first.
// If no record is found, it falls back to the members table.
// If no record is found in either table, it returns an error.
func (b *Buffalo) LookupEmail(ctx context.Context, v string) (*AccountRecord, error) {
	email := strings.TrimSpace(strings.ToLower(v))

	user, err := b.GetUserByEmail(ctx, email)
	if err == nil {
		return &AccountRecord{
			ID:          user.ID,
			Name:        user.Name,
			Email:       user.Email,
			IsActive:    user.IsActive,
			Role:        "platform",
			Password:    user.PasswordHash,
			SubjectType: "user",
		}, nil
	}

	if !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	member, err := b.GetMemberByEmail(ctx, email)
	if err == nil {
		return &AccountRecord{
			ID:          member.ID,
			Name:        member.Name,
			Email:       member.Email,
			IsActive:    member.IsActive,
			Role:        member.Role,
			Password:    member.PasswordHash,
			SubjectType: "member",
		}, nil
	}

	if !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("failed to get member: %w", err)
	}

	return nil, fmt.Errorf("no user or member found with email: %s", email)
}
