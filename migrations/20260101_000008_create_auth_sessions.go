package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

// CreateAuthSessions creates the table backing the active-session list and
// per-session termination.
type CreateAuthSessions struct{}

func (r *CreateAuthSessions) Signature() string {
	return "20260101_000008_create_auth_sessions"
}

func (r *CreateAuthSessions) Up() error {
	if facades.Schema().HasTable("auth_sessions") {
		return nil
	}
	return facades.Schema().Create("auth_sessions", func(table schema.Blueprint) {
		table.Uuid("id").Default(uuidDefault)
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
	return facades.Schema().DropIfExists("auth_sessions")
}
