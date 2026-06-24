package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

// DropUsersRoleDefault removes the legacy DB-level default ("admin") from
// users.role. Earlier installs created the column with `DEFAULT 'admin'`, which
// let a row inserted without an explicit role silently become an admin
// (privilege escalation). The role is now always set by the user-management
// service, so the column carries no default. Fresh installs already get no
// default (see 20260101_000001); this migration fixes existing databases.
//
// SQLite cannot ALTER a column's default and never benefits from this change
// (its create path already omits the default), so the migration is a no-op
// there.
type DropUsersRoleDefault struct {
	table     string
	signature string
}

func (r *DropUsersRoleDefault) Signature() string {
	return r.signature
}

func (r *DropUsersRoleDefault) Up() error {
	conn := facades.Schema().GetConnection()
	if facades.Config().GetString("database.connections."+conn+".driver") == "sqlite" {
		return nil
	}
	if !facades.Schema().HasColumn(r.table, "role") {
		return nil
	}
	// Change() re-emits the column definition without a default, which drops the
	// existing DB-level default on PostgreSQL / MySQL / SQL Server.
	return facades.Schema().Table(r.table, func(table schema.Blueprint) {
		table.Text("role").Change()
	})
}

func (r *DropUsersRoleDefault) Down() error {
	conn := facades.Schema().GetConnection()
	if facades.Config().GetString("database.connections."+conn+".driver") == "sqlite" {
		return nil
	}
	return facades.Schema().Table(r.table, func(table schema.Blueprint) {
		table.Text("role").Default("admin").Change()
	})
}
