package migrations

import "github.com/goravel/framework/contracts/database/schema"

// Migrations returns the package's code-based migrations in apply order. A
// consuming app appends these to its own registry:
//
//	func Migrations() []schema.Migration {
//	    return append(authmigrations.Migrations(), &app.CreateThings{})
//	}
func Migrations() []schema.Migration {
	return []schema.Migration{
		&CreateUsers{},
		&CreateAuditLogs{},
	}
}
