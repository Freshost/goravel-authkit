package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

// CreateAPITokens creates one personal-access-token table for an auth guard.
type CreateAPITokens struct {
	table     string
	signature string
}

func (r *CreateAPITokens) Signature() string { return r.signature }

func (r *CreateAPITokens) Up() error {
	if facades.Schema().HasTable(r.table) {
		return nil
	}
	return facades.Schema().Create(r.table, func(table schema.Blueprint) {
		table.Uuid("id")
		table.Primary("id")
		table.Uuid("user_id")
		table.String("name", 100)
		table.String("selector", 32)
		table.String("validator_hash", 64)
		table.Jsonb("scopes")
		table.TimestampTz("expires_at")
		table.TimestampTz("last_used_at").Nullable()
		table.TimestampTz("revoked_at").Nullable()
		table.TimestampTz("created_at").UseCurrent()
		table.Unique("selector")
		table.Index("user_id")
		table.Index("expires_at")
		table.Index("revoked_at")
	})
}

func (r *CreateAPITokens) Down() error { return facades.Schema().DropIfExists(r.table) }
