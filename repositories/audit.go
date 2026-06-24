package repositories

import (
	"context"

	"github.com/google/uuid"
	ormcontract "github.com/goravel/framework/contracts/database/orm"
	"github.com/goravel/framework/facades"

	"github.com/freshost/goravel-authkit/models"
)

// DefaultAuditTable is the table the bare NewAudit() constructor binds to.
const DefaultAuditTable = "audit_logs"

// AuditRepository persists and reads audit entries.
type AuditRepository interface {
	Create(ctx context.Context, entry *models.AuditLog) error
	// ListByActorActions returns the most recent entries for an actor whose
	// action is in actions, newest first, capped at limit.
	ListByActorActions(ctx context.Context, actorID uuid.UUID, actions []string, limit int) ([]models.AuditLog, error)
}

// Audit is the ORM-backed AuditRepository, bound to a concrete table.
type Audit struct{ table string }

// NewAudit returns an ORM-backed audit repository over the default table.
func NewAudit() *Audit { return NewAuditWithTable(DefaultAuditTable) }

// NewAuditWithTable returns an ORM-backed audit repository over the named table.
func NewAuditWithTable(table string) *Audit {
	if table == "" {
		table = DefaultAuditTable
	}
	return &Audit{table: table}
}

var _ AuditRepository = (*Audit)(nil)

func (r *Audit) query(ctx context.Context) ormcontract.Query {
	return facades.Orm().WithContext(ctx).Query().Table(r.table)
}

func (r *Audit) Create(ctx context.Context, entry *models.AuditLog) error {
	return r.query(ctx).Create(entry)
}

func (r *Audit) ListByActorActions(ctx context.Context, actorID uuid.UUID, actions []string, limit int) ([]models.AuditLog, error) {
	var entries []models.AuditLog
	if err := r.query(ctx).
		Where("actor_id", actorID).Where("action IN ?", actions).
		Order("created_at desc").Limit(limit).Find(&entries); err != nil {
		return nil, err
	}
	return entries, nil
}
