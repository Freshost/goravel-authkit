package oidc

import (
	"context"
	"github.com/google/uuid"
)

// Event contains identifiers only. Codes, bearer credentials and secrets must
// never be attached to audit or observability payloads.
type Event struct {
	Action                 string
	UserID                 uuid.UUID
	ClientID, ConnectionID string
}
type AuditFunc func(context.Context, Event)

func (s *Service) emit(ctx context.Context, event Event) {
	if s.config.Audit != nil {
		s.config.Audit(ctx, event)
	}
}
