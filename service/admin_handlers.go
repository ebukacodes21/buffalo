package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/ebukacodes21/buffalo/db"
	"github.com/ebukacodes21/buffalo/tooling"
)

var (
	ErrSlugTaken     = errors.New("an organization with that slug already exists")
	ErrAlreadyMember = errors.New("a member with that email already exists in this organization")
)

func isUniqueViolation(err error) bool {
	type coder interface{ SQLState() string }
	if c, ok := err.(coder); ok {
		return c.SQLState() == "23505"
	}
	return strings.Contains(err.Error(), "duplicate key")
}

func strNull(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}

// ── Organizations ──

func (b *Buffalo) ListOrgs(ctx context.Context, search string, limit int) ([]OrgListing, error) {
	rows, err := b.repo.ListOrgs(ctx, db.ListOrgsParams{
		Column1: search,
		Name:    "%" + search + "%",
		Limit:   int32(limit),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list organizations: %w", err)
	}

	out := make([]OrgListing, 0, len(rows))
	for _, r := range rows {
		out = append(out, OrgListing{
			Organization: Organization{
				ID:             r.ID.String(),
				Name:           r.Name,
				Slug:           r.Slug,
				Status:         r.Status,
				ProductID:      r.ProductID.String(),
				ProductName:    r.ProductName,
				RCNumber:       r.RcNumber.String,
				Sector:         r.Sector.String,
				AllocatedSeats: r.AllocatedSeats,
				CreatedAt:      r.CreatedAt,
				UpdatedAt:      r.UpdatedAt,
			},
			MemberCount: int(r.MemberCount),
		})
	}
	return out, nil
}

func (b *Buffalo) SetOrgStatus(ctx context.Context, orgID, status string) error {
	id, err := tooling.ParseUUID(orgID)
	if err != nil {
		return err
	}
	return b.repo.SetOrgStatus(ctx, db.SetOrgStatusParams{ID: id, Status: status})
}

func (b *Buffalo) Stats(ctx context.Context) (*Stats, error) {
	row, err := b.repo.DashboardStats(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load stats: %w", err)
	}
	return &Stats{
		Organizations: int(row.Organizations),
		ActiveOrgs:    int(row.ActiveOrgs),
		Users:         int(row.Users),
		Apps:          int(row.Apps),
		ActiveApps:    int(row.ActiveApps),
	}, nil
}

// ── Members ──

func (b *Buffalo) ListMembers(ctx context.Context, orgID string) ([]MemberListing, error) {
	id, err := tooling.ParseUUID(orgID)
	if err != nil {
		return nil, err
	}
	rows, err := b.repo.ListMembersByOrg(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to list members: %w", err)
	}

	out := make([]MemberListing, 0, len(rows))
	for _, r := range rows {
		out = append(out, MemberListing{
			ID:        r.ID.String(),
			OrgID:     r.OrgID.String(),
			Role:      r.Role,
			Email:     r.Email,
			Name:      r.Name,
			IsActive:  r.IsActive,
			CreatedAt: r.CreatedAt,
		})
	}
	return out, nil
}

func (b *Buffalo) GetMember(ctx context.Context, orgID, memberID string) (*Member, error) {
	oid, err := tooling.ParseUUID(orgID)
	if err != nil {
		return nil, err
	}
	mid, err := tooling.ParseUUID(memberID)
	if err != nil {
		return nil, err
	}
	m, err := b.repo.GetMemberByOrgAndID(ctx, db.GetMemberByOrgAndIDParams{OrgID: oid, ID: mid})
	if err != nil {
		return nil, err
	}
	return mapMember(m), nil
}

func (b *Buffalo) GetMemberByOrgAndEmail(ctx context.Context, orgID, email string) (*Member, error) {
	oid, err := tooling.ParseUUID(orgID)
	if err != nil {
		return nil, err
	}
	m, err := b.repo.GetMemberByOrgAndEmail(ctx, db.GetMemberByOrgAndEmailParams{
		OrgID: oid,
		Email: strings.ToLower(strings.TrimSpace(email)),
	})
	if err != nil {
		return nil, err
	}
	return mapMember(m), nil
}

func (b *Buffalo) CreateMember(ctx context.Context, orgID, role, email, passwordHash, name string, givenName, familyName, preferredUsername string) (*Member, error) {
	oid, err := tooling.ParseUUID(orgID)
	if err != nil {
		return nil, err
	}
	m, err := b.repo.CreateMember(ctx, db.CreateMemberParams{
		OrgID:             oid,
		Role:              role,
		Email:             strings.ToLower(strings.TrimSpace(email)),
		PasswordHash:      passwordHash,
		Name:              name,
		GivenName:         strNull(givenName),
		FamilyName:        strNull(familyName),
		PreferredUsername: strNull(preferredUsername),
		IsActive:          true,
	})
	if err != nil {
		if isUniqueViolation(err) {
			return nil, ErrAlreadyMember
		}
		return nil, err
	}
	return mapMember(m), nil
}

func (b *Buffalo) CountOwners(ctx context.Context, orgID string) (int, error) {
	id, err := tooling.ParseUUID(orgID)
	if err != nil {
		return 0, err
	}
	count, err := b.repo.CountMembersWithRole(ctx, db.CountMembersWithRoleParams{OrgID: id, Role: "owner"})
	if err != nil {
		return 0, err
	}
	return int(count), nil
}

func (b *Buffalo) UpdateMemberRole(ctx context.Context, orgID, memberID, role string) error {
	oid, err := tooling.ParseUUID(orgID)
	if err != nil {
		return err
	}
	mid, err := tooling.ParseUUID(memberID)
	if err != nil {
		return err
	}
	return b.repo.UpdateMemberRole(ctx, db.UpdateMemberRoleParams{OrgID: oid, ID: mid, Role: role})
}

func (b *Buffalo) RemoveMember(ctx context.Context, orgID, memberID string) error {
	oid, err := tooling.ParseUUID(orgID)
	if err != nil {
		return err
	}
	mid, err := tooling.ParseUUID(memberID)
	if err != nil {
		return err
	}
	return b.repo.RemoveMember(ctx, db.RemoveMemberParams{OrgID: oid, ID: mid})
}

// ── OAuth Clients ──

func (b *Buffalo) ListClients(ctx context.Context, search string, limit int) ([]*OauthClient, error) {
	rows, err := b.repo.ListOAuthClients(ctx, db.ListOAuthClientsParams{
		Column1: search,
		Name:    "%" + search + "%",
		Limit:   int32(limit),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list clients: %w", err)
	}

	out := make([]*OauthClient, 0, len(rows))
	for i := range rows {
		out = append(out, mapClient(rows[i]))
	}
	return out, nil
}

func (b *Buffalo) CreateClient(ctx context.Context, clientID, secret, name string, redirectURIs []string, baseURL string) (*OauthClient, error) {
	c, err := b.repo.CreateOAuthClient(ctx, db.CreateOAuthClientParams{
		ClientID:     clientID,
		ClientSecret: secret,
		Name:         name,
		RedirectUris: redirectURIs,
		BaseUrl:      baseURL,
	})
	if err != nil {
		return nil, err
	}
	return mapClient(c), nil
}

func (b *Buffalo) UpdateClient(ctx context.Context, id, name string, redirectURIs []string, isActive bool, baseURL string) error {
	uid, err := tooling.ParseUUID(id)
	if err != nil {
		return err
	}
	return b.repo.UpdateOAuthClient(ctx, db.UpdateOAuthClientParams{
		ID:           uid,
		Name:         name,
		RedirectUris: redirectURIs,
		IsActive:     isActive,
		BaseUrl:      baseURL,
	})
}

func (b *Buffalo) RotateClientSecret(ctx context.Context, id, secret string) error {
	uid, err := tooling.ParseUUID(id)
	if err != nil {
		return err
	}
	return b.repo.RotateOAuthClientSecret(ctx, db.RotateOAuthClientSecretParams{ID: uid, ClientSecret: secret})
}

// ── Entitlements ──

func (b *Buffalo) ListEntitlements(ctx context.Context, orgID string) ([]string, error) {
	id, err := tooling.ParseUUID(orgID)
	if err != nil {
		return nil, err
	}
	return b.repo.ListEntitlements(ctx, id)
}

func (b *Buffalo) SetEntitlements(ctx context.Context, orgID string, items []string) error {
	id, err := tooling.ParseUUID(orgID)
	if err != nil {
		return err
	}

	err = b.repo.ExecTx(ctx, func(q *db.Queries) error {
		if err := q.DeleteEntitlements(ctx, id); err != nil {
			return err
		}
		for _, key := range items {
			if err := q.UpsertEntitlement(ctx, db.UpsertEntitlementParams{OrgID: id, Entitlement: key}); err != nil {
				return err
			}
		}
		return nil
	})
	return err
}

// ── Users (admin) ──

func (b *Buffalo) ListUsers(ctx context.Context, search string, limit int) ([]UserRow, error) {
	rows, err := b.repo.ListUsers(ctx, db.ListUsersParams{
		Column1: search,
		Email:   "%" + search + "%",
		Limit:   int32(limit),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	out := make([]UserRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, UserRow{
			ID:              r.ID.String(),
			Email:           r.Email,
			Name:            r.Name,
			EmailVerified:   r.EmailVerified,
			IsActive:        r.IsActive,
			IsPlatformAdmin: r.IsPlatformAdmin,
			CreatedAt:       r.CreatedAt,
		})
	}
	return out, nil
}

func (b *Buffalo) SetUserActive(ctx context.Context, userID string, active bool) error {
	id, err := tooling.ParseUUID(userID)
	if err != nil {
		return err
	}
	return b.repo.SetUserActive(ctx, db.SetUserActiveParams{ID: id, IsActive: active})
}

// ── Audit ──

func (b *Buffalo) ListAuditEvents(ctx context.Context, orgID string, limit int) ([]AuditEvent, error) {
	rows, err := b.repo.ListAuditEvents(ctx, db.ListAuditEventsParams{Column1: orgID, Limit: int32(limit)})
	if err != nil {
		return nil, fmt.Errorf("failed to list audit events: %w", err)
	}

	out := make([]AuditEvent, 0, len(rows))
	for _, r := range rows {
		ev := AuditEvent{
			ID:        r.ID.String(),
			UserName:  r.UserName,
			OrgName:   r.OrgName,
			EventType: r.EventType,
			CreatedAt: r.CreatedAt,
		}
		if r.Details.Valid && len(r.Details.RawMessage) > 0 {
			_ = json.Unmarshal(r.Details.RawMessage, &ev.Details)
		}
		out = append(out, ev)
	}
	return out, nil
}

// ── Onboarding ──

func (b *Buffalo) OnboardBusiness(ctx context.Context, in OnboardInput) (*OnboardResult, error) {
	slug := in.Slug
	if slug == "" {
		slug = tooling.Slugify(in.OrgName)
	}

	prdID, err := tooling.ParseUUID(in.ProductID)
	if err != nil {
		return nil, err
	}

	hash, err := tooling.HashPassword(in.OwnerPassword)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	email := strings.ToLower(strings.TrimSpace(in.OwnerEmail))
	name := strings.TrimSpace(in.OwnerName)
	ownerName := strings.Fields(name)

	var given, family string
	if len(ownerName) > 0 {
		given = ownerName[0]
	}
	if len(ownerName) > 1 {
		family = ownerName[len(ownerName)-1]
	}

	result := &OnboardResult{}

	err = b.repo.ExecTx(ctx, func(q *db.Queries) error {
		org, err := q.CreateOrganization(ctx, db.CreateOrganizationParams{
			Name:        in.OrgName,
			Slug:        slug,
			ProductName: in.ProductName,
			ProductID:   prdID,
		})
		if err != nil {
			return err
		}

		member, err := q.CreateMember(ctx, db.CreateMemberParams{
			OrgID:             org.ID,
			Role:              "owner",
			Email:             email,
			PasswordHash:      hash,
			Name:              name,
			GivenName:         strNull(given),
			FamilyName:        strNull(family),
			PreferredUsername: strNull(email),
			IsActive:          true,
		})
		if err != nil {
			return err
		}

		result.Org = *mapOrg(org)
		result.Member = *mapMember(member)
		return nil
	})
	if err != nil {
		if isUniqueViolation(err) {
			return nil, tooling.ErrSlugTaken
		}
		return nil, err
	}

	return result, nil
}
