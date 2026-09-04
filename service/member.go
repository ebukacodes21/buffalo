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
	"github.com/google/uuid"
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
		SupervisorID:      uuidToStr(m.SupervisorID),
		PreferredUsername: m.PreferredUsername.String,
		CreatedAt:         m.CreatedAt,
		UpdatedAt:         m.UpdatedAt,
	}
}

// uuidToStr converts a nullable UUID to its string form, or "" when null.
func uuidToStr(u uuid.NullUUID) string {
	if !u.Valid || u.UUID == uuid.Nil {
		return ""
	}
	return u.UUID.String()
}

// SetSupervisor assigns the member's supervisor by UUID. An empty value clears
// the supervisor (null); the null UUID is normalized to empty.
func (b *Buffalo) SetSupervisor(ctx context.Context, orgID, memberID, supervisorID string) error {
	oid, err := tooling.ParseUUID(orgID)
	if err != nil {
		return err
	}
	mid, err := tooling.ParseUUID(memberID)
	if err != nil {
		return err
	}
	var sup uuid.UUID
	if strings.TrimSpace(supervisorID) != "" {
		sup, err = tooling.ParseUUID(supervisorID)
		if err != nil {
			return err
		}
	}
	return b.repo.UpdateMemberSupervisor(ctx, db.UpdateMemberSupervisorParams{
		OrgID: oid, ID: mid, SupervisorID: uuid.NullUUID{UUID: sup, Valid: sup != uuid.Nil},
	})
}

// SupervisorNameByID resolves a supervisor member's name from the org roster.
func supervisorNameByID(roster []MemberListing, supervisorID string) string {
	if strings.TrimSpace(supervisorID) == "" {
		return ""
	}
	for _, m := range roster {
		if m.ID == supervisorID {
			return m.Name
		}
	}
	return ""
}
