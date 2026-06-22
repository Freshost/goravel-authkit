package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

// CreateAuthRememberTokens creates the table backing the "remember me" feature
// (selector-validator persistent login tokens).
type CreateAuthRememberTokens struct{}

func (r *CreateAuthRememberTokens) Signature() string {
	return "20260101_000005_create_auth_remember_tokens"
}

func (r *CreateAuthRememberTokens) Up() error {
	if facades.Schema().HasTable("auth_remember_tokens") {
		return nil
	}
	return facades.Schema().Create("auth_remember_tokens", func(table schema.Blueprint) {
		table.Uuid("id").Default(uuidDefault)
		table.Primary("id")
		table.Uuid("user_id")
		table.String("selector", 64)
		table.String("validator_hash", 64)
		table.TimestampTz("expires_at")
		table.TimestampTz("created_at").UseCurrent()
		table.Unique("selector")
		table.Index("user_id")
		table.Index("expires_at")
	})
}

func (r *CreateAuthRememberTokens) Down() error {
	return facades.Schema().DropIfExists("auth_remember_tokens")
}
