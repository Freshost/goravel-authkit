package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

// AddTwoFactorLastUsed adds the column tracking the time-step of the last
// accepted TOTP code, used to reject replay within a code's validity window
// (single-use TOTP, OWASP ASVS 2.8.4). Idempotent.
type AddTwoFactorLastUsed struct{}

func (r *AddTwoFactorLastUsed) Signature() string {
	return "20260101_000004_add_two_factor_last_used"
}

func (r *AddTwoFactorLastUsed) Up() error {
	if facades.Schema().HasColumn("users", "two_factor_last_used_at") {
		return nil
	}
	return facades.Schema().Table("users", func(table schema.Blueprint) {
		table.TimestampTz("two_factor_last_used_at").Nullable()
	})
}

func (r *AddTwoFactorLastUsed) Down() error {
	if !facades.Schema().HasColumn("users", "two_factor_last_used_at") {
		return nil
	}
	return facades.Schema().Table("users", func(table schema.Blueprint) {
		table.DropColumn("two_factor_last_used_at")
	})
}
