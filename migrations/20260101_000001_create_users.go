// Package migrations holds the code-based migrations owned by goravel-authkit. A
// consuming app appends Migrations() to its own migration registry (see
// bootstrap/migrations.go) so the framework runner applies them in order. Each
// migration is idempotent.
package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

// CreateUsers creates the canonical users table backing authentication. The
// first admin is created by the `auth:create-user` command or an app installer;
// this migration only owns the schema.
type CreateUsers struct{}

func (r *CreateUsers) Signature() string {
	return "20260101_000001_create_users"
}

func (r *CreateUsers) Up() error {
	if facades.Schema().HasTable("users") {
		return nil
	}
	return facades.Schema().Create("users", func(table schema.Blueprint) {
		// No DB-side default: every insert sets the id in Go (uuid.New()), so the
		// schema stays driver-agnostic (a gen_random_uuid() default breaks SQLite).
		table.Uuid("id")
		table.Primary("id")
		table.Text("name").Nullable()
		table.String("email", 255)
		table.TimestampTz("email_verified").Nullable()
		table.Text("image").Nullable()
		// Nullable so a future OAuth/passwordless flow needs no schema change.
		// The credentials flow stamps it (bcrypt cost 12).
		table.Text("password_hash").Nullable()
		// Stamped on every password change; compared per-request for session
		// invalidation.
		table.TimestampTz("password_changed_at").UseCurrent()
		table.Text("role").Default("admin")
		table.TimestampTz("created_at").UseCurrent()
		table.TimestampTz("updated_at").UseCurrent()
		table.Unique("email")
	})
}

func (r *CreateUsers) Down() error {
	return facades.Schema().DropIfExists("users")
}
