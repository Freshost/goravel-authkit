package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

// CreateAuthSessions creates the table backing the active-session list and
// per-session termination.
type CreateAuthSessions struct {
	table     string
	signature string
}

func (r *CreateAuthSessions) Signature() string {
	return r.signature
}

func (r *CreateAuthSessions) Up() error {
	if facades.Schema().HasTable(r.table) {
		return nil
	}
	return facades.Schema().Create(r.table, func(table schema.Blueprint) {
		table.Uuid("id")
		table.Primary("id")
		table.String("session_id", 255)
		table.Uuid("user_id")
		table.String("ip", 64).Nullable()
		table.Text("user_agent").Nullable()
		table.TimestampTz("created_at").UseCurrent()
		table.TimestampTz("last_active_at")
		table.Unique("session_id")
		table.Index("user_id")
		table.Index("last_active_at")
	})
}

func (r *CreateAuthSessions) Down() error {
	return facades.Schema().DropIfExists(r.table)
}
