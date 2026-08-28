package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ebukacodes21/buffalo/db"
	"github.com/ebukacodes21/buffalo/tooling"
)

func (b *Buffalo) GetMemberByID(ctx context.Context, id string) (*Member, error) {
	uid, err := tooling.ParseUUID(id)
	if err != nil {
		return nil, err
	}

	m, err := b.repo.GetMemberByID(ctx, uid)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		return nil, fmt.Errorf("failed to get member: %w", err)
	}

	return mapMember(m), nil
}

func (b *Buffalo) GetMemberByEmail(ctx context.Context, email string) (*Member, error) {
	email = strings.TrimSpace(strings.ToLower(email))

	m, err := b.repo.GetMemberByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		return nil, fmt.Errorf("failed to get member: %w", err)
	}

	return mapMember(m), nil
}

func (b *Buffalo) CreatePasswordReset(ctx context.Context, memberID, token string, duration time.Time) error {
	uid, err := tooling.ParseUUID(memberID)
	if err != nil {
		return err
	}

	return b.repo.CreatePasswordReset(ctx, db.CreatePasswordResetParams{
		SubjectID: uid,
		Token:     token,
		ExpiresAt: duration,
	})
}

func (b *Buffalo) GetPasswordReset(ctx context.Context, v string) (string, error) {
	uid, err := b.repo.GetPasswordReset(ctx, v)
	if err != nil {
		return "", err
	}
	return uid.String(), nil
}

func (b *Buffalo) UpdatePasswordHash(ctx context.Context, memberID, hash string) error {
	uid, err := tooling.ParseUUID(memberID)
	if err != nil {
		return err
	}

	return b.repo.UpdateMemberPasswordHash(ctx, db.UpdateMemberPasswordHashParams{
		ID:           uid,
		PasswordHash: hash,
	})
}

func (b *Buffalo) MarkPasswordResetUsed(ctx context.Context, token string) error {
	return b.repo.MarkPasswordResetUsed(ctx, token)
}

func (b *Buffalo) ListMembershipForMember(ctx context.Context, memberID string) (*Organization, error) {
	id, err := tooling.ParseUUID(memberID)
	if err != nil {
		return nil, err
	}

	rows, err := b.repo.ListMembershipsForMember(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("unable to list membership for member: %s", err.Error())
	}

	for _, m := range rows {
		return &Organization{
			ID:             m.ID.String(),
			Name:           m.Name,
			Slug:           m.Slug,
			Status:         "active",
			RCNumber:       m.RcNumber,
			Sector:         m.Sector,
			AllocatedSeats: m.AllocatedSeats,
		}, nil
	}

	return nil, nil
}

func mapMember(m db.MembersAccount) *Member {
	return &Member{
		ID:                m.ID.String(),
		OrgID:             m.OrgID.String(),
		Role:              m.Role,
		IsActive:          m.IsActive,
		Email:             m.Email,
		EmailVerified:     m.EmailVerified,
		PasswordHash:      m.PasswordHash,
		Name:              m.Name,
		GivenName:         m.GivenName.String,
		FamilyName:        m.FamilyName.String,
		Picture:           m.Picture.String,
		PreferredUsername: m.PreferredUsername.String,
		CreatedAt:         m.CreatedAt,
		UpdatedAt:         m.UpdatedAt,
	}
}
