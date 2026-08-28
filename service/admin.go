package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/ebukacodes21/buffalo/db"
	"github.com/ebukacodes21/buffalo/tooling"
)

func (b *Buffalo) GetUserByID(ctx context.Context, userID string) (*User, error) {
	id, err := tooling.ParseUUID(userID)
	if err != nil {
		return nil, err
	}

	user, err := b.repo.GetUserByID(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return mapUser(user), nil
}

func (b *Buffalo) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	user, err := b.repo.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return mapUser(user), nil
}

func mapUser(user db.User) *User {
	return &User{
		Sub:               user.ID.String(),
		ID:                user.ID.String(),
		Email:             user.Email,
		EmailVerified:     user.EmailVerified,
		IsPlatformAdmin:   user.IsPlatformAdmin,
		PasswordHash:      user.PasswordHash,
		IsActive:          user.IsActive,
		Picture:           user.Picture.String,
		PreferredUsername: user.PreferredUsername.String,
		CreatedAt:         user.CreatedAt,
		Name:              user.Name,
		GivenName:         user.GivenName.String,
		FamilyName:        user.FamilyName.String,
	}
}
