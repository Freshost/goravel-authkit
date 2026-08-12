package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"

	"github.com/freshost/goravel-authkit/repositories"
)

// MigrationConfig names the tables a parameterised migration set operates on.
// Empty fields fall back to the package defaults.
type MigrationConfig struct {
	UsersTable          string
	AuditTable          string
	RememberTokensTable string
	SessionsTable       string
	APITokensTable      string
}

func (c MigrationConfig) withDefaults() MigrationConfig {
	if c.UsersTable == "" {
		c.UsersTable = repositories.DefaultUsersTable
	}
	if c.AuditTable == "" {
		c.AuditTable = repositories.DefaultAuditTable
	}
	if c.RememberTokensTable == "" {
		c.RememberTokensTable = repositories.DefaultRememberTokensTable
	}
	if c.SessionsTable == "" {
		c.SessionsTable = repositories.DefaultSessionsTable
	}
	if c.APITokensTable == "" {
		c.APITokensTable = repositories.DefaultAPITokensTable
	}
	return c
}

// Migrations returns the package's code-based migrations for the DEFAULT tables.
// It is exactly ForTables with an empty config, so single- and multi-guard apps
// share one signature scheme (authkit_<table>_<step>). The ServiceProvider
// self-registers per-guard migrations at boot unless authkit.register_migrations
// is false; this stays exported for hosts that register migrations by hand.
func Migrations() []schema.Migration {
	return ForTables(MigrationConfig{})
}

// ForTables returns the migration set parameterised by cfg's table names, with
// table-derived signatures (authkit_<table>_<step>) so a host running several
// guards can register one set per user domain without signature collisions. Every
// Up is idempotent: a create skips when the table already exists, an alter skips
// when the column already exists — so reshaping a host's existing table only adds
// authkit's missing columns.
func ForTables(cfg MigrationConfig) []schema.Migration {
	cfg = cfg.withDefaults()
	sig := func(table, step string) string { return "authkit_" + table + "_" + step }
	return []schema.Migration{
		&CreateUsers{table: cfg.UsersTable, signature: sig(cfg.UsersTable, "create")},
		&CreateAuditLogs{table: cfg.AuditTable, signature: sig(cfg.AuditTable, "create")},
		&AddTwoFactorToUsers{table: cfg.UsersTable, signature: sig(cfg.UsersTable, "two_factor")},
		&AddTwoFactorLastUsed{table: cfg.UsersTable, signature: sig(cfg.UsersTable, "two_factor_last_used")},
		&CreateAuthRememberTokens{table: cfg.RememberTokensTable, signature: sig(cfg.RememberTokensTable, "create")},
		&AddRememberTokenRotation{table: cfg.RememberTokensTable, signature: sig(cfg.RememberTokensTable, "rotation")},
		&AddDisabledAtToUsers{table: cfg.UsersTable, signature: sig(cfg.UsersTable, "disabled_at")},
		&CreateAuthSessions{table: cfg.SessionsTable, signature: sig(cfg.SessionsTable, "create")},
		&DropUsersRoleDefault{table: cfg.UsersTable, signature: sig(cfg.UsersTable, "role_no_default")},
		&CreateAPITokens{table: cfg.APITokensTable, signature: sig(cfg.APITokensTable, "create")},
		&AddAuditLoginIndex{table: cfg.AuditTable, signature: sig(cfg.AuditTable, "login_index")},
	}
}
