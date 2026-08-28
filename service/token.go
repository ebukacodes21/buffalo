package service

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/ebukacodes21/buffalo/db"
	"github.com/ebukacodes21/buffalo/tooling"
)

func (b *Buffalo) CreateRefreshToken(refreshToken, clientID, subjectType, subjectID, scope string, duration time.Time) error {
	id, err := tooling.ParseUUID(subjectID)
	if err != nil {
		return err
	}

	args := db.CreateRefreshTokenParams{
		Token:       refreshToken,
		ClientID:    clientID,
		SubjectType: subjectType,
		SubjectID:   id,
		Scope:       sql.NullString{String: scope, Valid: scope != ""},
		ExpiresAt:   duration,
	}

	return b.repo.CreateRefreshToken(context.Background(), args)
}

func (b *Buffalo) GetRefreshToken(v string) (string, string, string, string, error) {
	row, err := b.repo.GetRefreshToken(context.Background(), v)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", "", "", err
		}
		return "", "", "", "", err
	}
	return row.ClientID, row.SubjectType, row.SubjectID.String(), row.Scope.String, nil
}

func (b *Buffalo) RevokeRefreshToken(v string) error {
	return b.repo.RevokeRefreshToken(context.Background(), v)
}
