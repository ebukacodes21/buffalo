package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	repo "github.com/ebukacodes21/buffalo/db"
	"github.com/ebukacodes21/buffalo/tooling"
)

func (b *Buffalo) GetActiveClientByClientID(ctx context.Context, clientID string) (*OauthClient, error) {
	org, err := b.repo.GetActiveClientByClientID(ctx, clientID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("no oauth client found with id: %s", clientID)
		}
		return nil, fmt.Errorf("failed to load organisation. err: %s", err.Error())
	}

	return mapClient(org), nil
}

func (b *Buffalo) GetClientByID(ctx context.Context, ID string) (*OauthClient, error) {
	id, err := tooling.ParseUUID(ID)
	if err != nil {
		return nil, err
	}

	org, err := b.repo.GetClientByID(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("no oauth client found with id: %s", id)
		}
		return nil, fmt.Errorf("failed to load organisation. err: %s", err.Error())
	}

	return mapClient(org), nil
}

func mapClient(client repo.OauthClient) *OauthClient {
	return &OauthClient{
		ID:            client.ID.String(),
		ClientID:      client.ClientID,
		ClientSecret:  client.ClientSecret,
		BaseUrl:       client.BaseUrl,
		Name:          client.Name,
		RedirectUris:  client.RedirectUris,
		ResponseTypes: client.ResponseTypes,
		IsActive:      client.IsActive,
		CreatedAt:     client.CreatedAt,
		GrantTypes:    client.GrantTypes,
	}
}
