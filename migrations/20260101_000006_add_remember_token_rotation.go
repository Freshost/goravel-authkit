package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

// AddRememberTokenRotation adds the grace-window rotation columns to
// auth_remember_tokens so a just-superseded validator is tolerated for a short
// window (concurrent-request safety) instead of being mistaken for theft.
type AddRememberTokenRotation struct {
	table     string
	signature string
}

func (r *AddRememberTokenRotation) Signature() string {
	return r.signature
}

func (r *AddRememberTokenRotation) Up() error {
	if !facades.Schema().HasTable(r.table) {
		return nil
	}
	if facades.Schema().HasColumn(r.table, "previous_validator_hash") {
		return nil
	}
	return facades.Schema().Table(r.table, func(table schema.Blueprint) {
		table.String("previous_validator_hash", 64).Default("")
		table.TimestampTz("rotated_at").Nullable()
	})
}

func (r *AddRememberTokenRotation) Down() error {
	return facades.Schema().Table(r.table, func(table schema.Blueprint) {
		table.DropColumn("previous_validator_hash", "rotated_at")
	})
}
