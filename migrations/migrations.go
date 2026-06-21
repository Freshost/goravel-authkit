package migrations

import "github.com/goravel/framework/contracts/database/schema"

// Migrations returns the package's code-based migrations in apply order. The
// ServiceProvider self-registers these via the schema facade at boot, so a
// consuming app does not wire them by hand.
func Migrations() []schema.Migration {
	return []schema.Migration{
		&CreateUsers{},
		&CreateAuditLogs{},
		&AddTwoFactorToUsers{},
		&AddTwoFactorLastUsed{},
	}
}
