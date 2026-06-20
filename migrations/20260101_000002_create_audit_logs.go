package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

// CreateAuditLogs creates the audit_logs table written by the audit service.
type CreateAuditLogs struct{}

func (r *CreateAuditLogs) Signature() string {
	return "20260101_000002_create_audit_logs"
}

func (r *CreateAuditLogs) Up() error {
	if facades.Schema().HasTable("audit_logs") {
		return nil
	}
	return facades.Schema().Create("audit_logs", func(table schema.Blueprint) {
		table.Uuid("id").Default(uuidDefault)
		table.Primary("id")
		table.Uuid("actor_id").Nullable()
		table.String("actor_email", 255).Nullable()
		table.String("action", 255)
		table.String("resource_type", 255).Nullable()
		table.String("resource_id", 255).Nullable()
		table.Jsonb("metadata").Nullable()
		table.String("ip", 64).Nullable()
		table.TimestampTz("created_at").UseCurrent()
		table.Index("actor_id")
		table.Index("resource_type", "resource_id")
	})
}

func (r *CreateAuditLogs) Down() error {
	return facades.Schema().DropIfExists("audit_logs")
}
