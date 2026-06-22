package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

// AddRememberTokenRotation adds the grace-window rotation columns to
// auth_remember_tokens so a just-superseded validator is tolerated for a short
// window (concurrent-request safety) instead of being mistaken for theft.
type AddRememberTokenRotation struct{}

func (r *AddRememberTokenRotation) Signature() string {
	return "20260101_000006_add_remember_token_rotation"
}

func (r *AddRememberTokenRotation) Up() error {
	if !facades.Schema().HasTable("auth_remember_tokens") {
		return nil
	}
	if facades.Schema().HasColumn("auth_remember_tokens", "previous_validator_hash") {
		return nil
	}
	return facades.Schema().Table("auth_remember_tokens", func(table schema.Blueprint) {
		table.String("previous_validator_hash", 64).Default("")
		table.TimestampTz("rotated_at").Nullable()
	})
}

func (r *AddRememberTokenRotation) Down() error {
	return facades.Schema().Table("auth_remember_tokens", func(table schema.Blueprint) {
		table.DropColumn("previous_validator_hash", "rotated_at")
	})
}
