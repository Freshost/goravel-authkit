package repositories

import (
	"context"
	"time"

	"github.com/google/uuid"
	ormcontract "github.com/goravel/framework/contracts/database/orm"
	"github.com/goravel/framework/facades"
)

// LoginEventRecord is the persistence projection used by the administrator
// sign-in overview. UserName/UserEmail come from the live user when it still
// exists; Email falls back to the immutable address captured in the audit row.
type LoginEventRecord struct {
	ID        uuid.UUID  `gorm:"column:id"`
	UserID    *uuid.UUID `gorm:"column:user_id"`
	UserName  *string    `gorm:"column:user_name"`
	UserEmail string     `gorm:"column:user_email"`
	Action    string     `gorm:"column:action"`
	IP        string     `gorm:"column:ip"`
	CreatedAt time.Time  `gorm:"column:created_at"`
}

// LoginEventsRepository reads successful sign-ins across a guard.
type LoginEventsRepository interface {
	List(ctx context.Context, actions []string, page, perPage int) ([]LoginEventRecord, int64, error)
}

// LoginEvents is the table-aware ORM implementation.
type LoginEvents struct {
	auditTable string
	usersTable string
}

// NewLoginEvents binds the administrator sign-in query to one guard's tables.
func NewLoginEvents(auditTable, usersTable string) *LoginEvents {
	if auditTable == "" {
		auditTable = DefaultAuditTable
	}
	if usersTable == "" {
		usersTable = DefaultUsersTable
	}
	return &LoginEvents{auditTable: auditTable, usersTable: usersTable}
}

var _ LoginEventsRepository = (*LoginEvents)(nil)

func (r *LoginEvents) query(ctx context.Context) ormcontract.Query {
	return facades.Orm().WithContext(ctx).Query().Table(r.auditTable + " AS audit")
}

// List returns one page ordered newest first and the total matching row count.
func (r *LoginEvents) List(ctx context.Context, actions []string, page, perPage int) ([]LoginEventRecord, int64, error) {
	total, err := r.query(ctx).Where("audit.action IN ?", actions).Count()
	if err != nil {
		return nil, 0, err
	}

	rows := make([]LoginEventRecord, 0, perPage)
	err = r.query(ctx).
		Select(
			"audit.id, audit.actor_id AS user_id, users.name AS user_name, "+
				"COALESCE(users.email, audit.actor_email) AS user_email, "+
				"audit.action, audit.ip, audit.created_at",
		).
		Join("LEFT JOIN "+r.usersTable+" AS users ON users.id = audit.actor_id").
		Where("audit.action IN ?", actions).
		OrderByRaw("audit.created_at DESC, audit.id DESC").
		Offset((page - 1) * perPage).
		Limit(perPage).
		Get(&rows)
	if err != nil {
		return nil, 0, err
	}
	return rows, total, nil
}
