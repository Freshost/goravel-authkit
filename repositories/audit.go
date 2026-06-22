package repositories

import (
	"context"

	"github.com/google/uuid"
	"github.com/goravel/framework/facades"

	"github.com/freshost/goravel-authkit/models"
)

// AuditRepository persists and reads audit entries.
type AuditRepository interface {
	Create(ctx context.Context, entry *models.AuditLog) error
	// ListByActorActions returns the most recent entries for an actor whose
	// action is in actions, newest first, capped at limit.
	ListByActorActions(ctx context.Context, actorID uuid.UUID, actions []string, limit int) ([]models.AuditLog, error)
}

// Audit is the ORM-backed AuditRepository.
type Audit struct{}

// NewAudit returns an ORM-backed audit repository.
func NewAudit() *Audit {
	return &Audit{}
}

var _ AuditRepository = (*Audit)(nil)

func (r *Audit) Create(ctx context.Context, entry *models.AuditLog) error {
	return facades.Orm().WithContext(ctx).Query().Create(entry)
}

func (r *Audit) ListByActorActions(ctx context.Context, actorID uuid.UUID, actions []string, limit int) ([]models.AuditLog, error) {
	var entries []models.AuditLog
	if err := facades.Orm().WithContext(ctx).Query().
		Where("actor_id", actorID).Where("action IN ?", actions).
		Order("created_at desc").Limit(limit).Find(&entries); err != nil {
		return nil, err
	}
	return entries, nil
}
