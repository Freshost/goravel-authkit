package services

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/freshost/goravel-authkit/models"
	"github.com/freshost/goravel-authkit/repositories"
)

// AuditEntry is the input to the audit service — shaped like a future event
// payload so audit can move to an event/queue pipeline later without changing
// callers.
type AuditEntry struct {
	ActorID      *uuid.UUID
	ActorEmail   string
	Action       string
	ResourceType string
	ResourceID   *string
	Metadata     map[string]any
	IP           string
}

// Audit is the single chokepoint for writing audit entries.
type Audit struct {
	repo repositories.AuditRepository
}

// NewAudit builds the audit service.
func NewAudit(repo repositories.AuditRepository) *Audit {
	return &Audit{repo: repo}
}

// Log writes an audit entry. Audit is best-effort context for operators; callers
// decide whether a failure here should fail the parent operation.
func (s *Audit) Log(ctx context.Context, e AuditEntry) error {
	entry := &models.AuditLog{
		ID:           uuid.New(),
		ActorID:      e.ActorID,
		ActorEmail:   e.ActorEmail,
		Action:       e.Action,
		ResourceType: e.ResourceType,
		ResourceID:   e.ResourceID,
		Metadata:     models.JSONMap(e.Metadata),
		IP:           e.IP,
	}
	if err := s.repo.Create(ctx, entry); err != nil {
		return fmt.Errorf("write audit log: %w", err)
	}
	return nil
}
