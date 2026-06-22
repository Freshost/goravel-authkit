package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

// AddDisabledAtToUsers adds the account-lock column: a non-null disabled_at
// refuses login and rejects any live session / remember cookie.
type AddDisabledAtToUsers struct{}

func (r *AddDisabledAtToUsers) Signature() string {
	return "20260101_000007_add_disabled_at_to_users"
}

func (r *AddDisabledAtToUsers) Up() error {
	if facades.Schema().HasColumn("users", "disabled_at") {
		return nil
	}
	return facades.Schema().Table("users", func(table schema.Blueprint) {
		table.TimestampTz("disabled_at").Nullable()
	})
}

func (r *AddDisabledAtToUsers) Down() error {
	return facades.Schema().Table("users", func(table schema.Blueprint) {
		table.DropColumn("disabled_at")
	})
}
