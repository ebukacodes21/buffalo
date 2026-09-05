package service

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ebukacodes21/buffalo/db"
	"github.com/ebukacodes21/buffalo/tooling"
	"github.com/google/uuid"
)

func (b *Buffalo) InsertAuditEvent(ctx context.Context, actorID, orgID, eventType, client_ip, user_agent string, details map[string]interface{}) error {
	userID := nullUUID(actorID)
	id := nullUUID(orgID)

	// Marshal to a string, not []byte: pgx's simple-protocol mode (required
	// behind transaction poolers) would otherwise send []byte as a bytea
	// literal, which has no cast to the jsonb details column.
	var payload string
	if len(details) > 0 {
		b, err := json.Marshal(details)
		if err != nil {
			return fmt.Errorf("marshal audit details: %w", err)
		}
		payload = string(b)
	}

	args := db.InsertAuditEventParams{
		UserID:    userID,
		OrgID:     id,
		EventType: eventType,
		Column4:   payload,
	}

	_, err := b.repo.InsertAuditEvent(ctx, args)
	if err != nil {
		return fmt.Errorf("failed to audit event. err: %s", err.Error())
	}

	return nil
}

// nullUUID parses v into a nullable UUID. An empty or unparsable value maps
// to NULL so optional audit references (org or actor) don't fail the write.
func nullUUID(v string) uuid.NullUUID {
	if v == "" {
		return uuid.NullUUID{Valid: false}
	}
	id, err := tooling.ParseUUID(v)
	if err != nil {
		return uuid.NullUUID{Valid: false}
	}
	return uuid.NullUUID{Valid: true, UUID: id}
}
