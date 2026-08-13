package repositories

import (
	"context"
	"strings"
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
	List(ctx context.Context, filter LoginEventFilter, page, perPage int) ([]LoginEventRecord, int64, error)
}

// LoginEventFilter is the normalized persistence query for administrator
// sign-in activity. MethodAction is an audit action, not a transport value.
type LoginEventFilter struct {
	Actions      []string
	User         string
	IP           string
	MethodAction string
	OldestFirst  bool
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

// List returns one filtered page and the total matching row count.
func (r *LoginEvents) List(ctx context.Context, filter LoginEventFilter, page, perPage int) ([]LoginEventRecord, int64, error) {
	countQuery := r.filteredQuery(ctx, filter)
	total, err := countQuery.Count()
	if err != nil {
		return nil, 0, err
	}

	order := "audit.created_at DESC, audit.id DESC"
	if filter.OldestFirst {
		order = "audit.created_at ASC, audit.id ASC"
	}

	rows := make([]LoginEventRecord, 0, perPage)
	err = r.filteredQuery(ctx, filter).
		Select(
			"audit.id, audit.actor_id AS user_id, users.name AS user_name, " +
				"COALESCE(users.email, audit.actor_email) AS user_email, " +
				"audit.action, audit.ip, audit.created_at",
		).
		OrderByRaw(order).
		Offset((page - 1) * perPage).
		Limit(perPage).
		Get(&rows)
	if err != nil {
		return nil, 0, err
	}
	return rows, total, nil
}

func (r *LoginEvents) filteredQuery(ctx context.Context, filter LoginEventFilter) ormcontract.Query {
	query := r.query(ctx).
		Join("LEFT JOIN "+r.usersTable+" AS users ON users.id = audit.actor_id").
		Where("audit.action IN ?", filter.Actions)
	if filter.MethodAction != "" {
		query = query.Where("audit.action = ?", filter.MethodAction)
	}
	if filter.User != "" {
		pattern := literalContainsPattern(filter.User)
		query = query.Where(
			"(LOWER(COALESCE(users.name, '')) LIKE ? ESCAPE '!' OR "+
				"LOWER(COALESCE(users.email, audit.actor_email, '')) LIKE ? ESCAPE '!')",
			pattern, pattern,
		)
	}
	if filter.IP != "" {
		query = query.Where(
			"LOWER(COALESCE(audit.ip, '')) LIKE ? ESCAPE '!'",
			literalContainsPattern(filter.IP),
		)
	}
	return query
}

func literalContainsPattern(value string) string {
	value = strings.ToLower(value)
	value = strings.ReplaceAll(value, "!", "!!")
	value = strings.ReplaceAll(value, "%", "!%")
	value = strings.ReplaceAll(value, "_", "!_")
	return "%" + value + "%"
}
