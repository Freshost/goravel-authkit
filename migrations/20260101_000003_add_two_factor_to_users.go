package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

// AddTwoFactorToUsers adds the TOTP two-factor columns to the users table. The
// secret and recovery codes are stored encrypted (via the Crypt facade) by the
// service layer; this migration only owns the schema. Idempotent.
type AddTwoFactorToUsers struct {
	table     string
	signature string
}

func (r *AddTwoFactorToUsers) Signature() string {
	return r.signature
}

func (r *AddTwoFactorToUsers) Up() error {
	if facades.Schema().HasColumn(r.table, "two_factor_secret") {
		return nil
	}
	return facades.Schema().Table(r.table, func(table schema.Blueprint) {
		// Encrypted TOTP secret; null until the user enrolls.
		table.Text("two_factor_secret").Nullable()
		// Encrypted JSON array of single-use recovery codes; null until confirmed.
		table.Text("two_factor_recovery_codes").Nullable()
		// Set when the user confirms enrollment; null = 2FA not active.
		table.TimestampTz("two_factor_confirmed_at").Nullable()
	})
}

func (r *AddTwoFactorToUsers) Down() error {
	if !facades.Schema().HasColumn(r.table, "two_factor_secret") {
		return nil
	}
	return facades.Schema().Table(r.table, func(table schema.Blueprint) {
		table.DropColumn("two_factor_secret", "two_factor_recovery_codes", "two_factor_confirmed_at")
	})
}
