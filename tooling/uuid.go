package tooling

import (
	"fmt"

	"github.com/google/uuid"
)

func ParseUUID(v string) (uuid.UUID, error) {
	id, err := uuid.Parse(v)
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("invalid id: %s, err: %s", id, err.Error())
	}

	return id, nil
}
