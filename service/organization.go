package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/ebukacodes21/buffalo/db"
	"github.com/google/uuid"
)

func (b *Buffalo) GetOrgByID(ctx context.Context, orgID string) (*Organization, error) {
	id, err := uuid.Parse(orgID)
	if err != nil {
		return nil, fmt.Errorf("invalid organisation id: %s, err: %s", orgID, err.Error())
	}

	org, err := b.repo.GetOrgByID(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("no organisation found with id: %s", orgID)
		}
		return nil, fmt.Errorf("failed to load organisation. err: %s", err.Error())
	}

	return mapOrg(org), nil
}

func mapOrg(org db.Organization) *Organization {
	return &Organization{
		ID:             org.ID.String(),
		Name:           org.Name,
		Slug:           org.Slug,
		Status:         org.Status,
		ProductName:    org.ProductName,
		ProductID:      org.ProductID.String(),
		RCNumber:       org.RcNumber,
		Sector:         org.Sector,
		AllocatedSeats: org.AllocatedSeats,
		CreatedAt:      org.CreatedAt,
		UpdatedAt:      org.UpdatedAt,
	}
}
