package bootstrap

import (
	"github.com/goravel/framework/contracts/database/schema"

	"goravel/database/migrations"
)

// Migrations holds only the app's own migrations. Both authkit guards' tables
// (the admin and client sets) are auto-registered by the authkit ServiceProvider
// from the authkit.guards config, so they are not listed here.
func Migrations() []schema.Migration {
	return []schema.Migration{
		&migrations.M20210101000001CreateJobsTable{},
	}
}
