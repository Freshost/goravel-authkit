package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

// AddTwoFactorVersion preserves credential history across disable/re-enrollment.
type AddTwoFactorVersion struct{ table, signature string }

func (m *AddTwoFactorVersion) Signature() string { return m.signature }
func (m *AddTwoFactorVersion) Up() error {
	if facades.Schema().HasColumn(m.table, "two_factor_version") {
		return nil
	}
	return facades.Schema().Table(m.table, func(t schema.Blueprint) { t.BigInteger("two_factor_version").Default(0) })
}
func (m *AddTwoFactorVersion) Down() error { return nil } // Retain security history on rollback.

// BindRememberCredentials requires proof from the original password verification.
type BindRememberCredentials struct{ table, signature string }

func (m *BindRememberCredentials) Signature() string { return m.signature }
func (m *BindRememberCredentials) Up() error {
	if !facades.Schema().HasColumn(m.table, "credential_stamp") {
		if err := facades.Schema().Table(m.table, func(t schema.Blueprint) { t.TimestampTz("credential_stamp", 6).Nullable() }); err != nil {
			return err
		}
	}
	if !facades.Schema().HasColumn(m.table, "session_id") {
		return facades.Schema().Table(m.table, func(t schema.Blueprint) { t.String("session_id", 255).Default(""); t.Index("session_id") })
	}
	return nil
}
func (m *BindRememberCredentials) Down() error { return nil } // Do not restore unbound credentials on rollback.
