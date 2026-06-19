package repositories

import (
	"context"

	"github.com/goravel/framework/facades"

	"github.com/freshost/goravel-auth/models"
)

// AuditRepository persists audit entries.
type AuditRepository interface {
	Create(ctx context.Context, entry *models.AuditLog) error
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
