package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

// AddTwoFactorLastUsed adds the column tracking the time-step of the last
// accepted TOTP code, used to reject replay within a code's validity window
// (single-use TOTP, OWASP ASVS 2.8.4). Idempotent.
type AddTwoFactorLastUsed struct {
	table     string
	signature string
}

func (r *AddTwoFactorLastUsed) Signature() string {
	return r.signature
}

func (r *AddTwoFactorLastUsed) Up() error {
	if facades.Schema().HasColumn(r.table, "two_factor_last_used_at") {
		return nil
	}
	return facades.Schema().Table(r.table, func(table schema.Blueprint) {
		table.TimestampTz("two_factor_last_used_at").Nullable()
	})
}

func (r *AddTwoFactorLastUsed) Down() error {
	if !facades.Schema().HasColumn(r.table, "two_factor_last_used_at") {
		return nil
	}
	return facades.Schema().Table(r.table, func(table schema.Blueprint) {
		table.DropColumn("two_factor_last_used_at")
	})
}
