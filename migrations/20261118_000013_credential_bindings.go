package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

// CredentialBindings preserves credential history across MFA disable/re-enrollment.
type CredentialBindings struct{ users, remember, signature string }

func (m *CredentialBindings) Signature() string { return m.signature }
func (m *CredentialBindings) Up() error {
	if !facades.Schema().HasColumn(m.users, "two_factor_version") {
		if err := facades.Schema().Table(m.users, func(t schema.Blueprint) { t.BigInteger("two_factor_version").Default(0) }); err != nil {
			return err
		}
	}
	if !facades.Schema().HasColumn(m.remember, "credential_stamp") {
		if err := facades.Schema().Table(m.remember, func(t schema.Blueprint) { t.TimestampTz("credential_stamp", 6).Nullable() }); err != nil {
			return err
		}
	}
	if !facades.Schema().HasColumn(m.remember, "session_id") {
		return facades.Schema().Table(m.remember, func(t schema.Blueprint) { t.String("session_id", 255).Default(""); t.Index("session_id") })
	}
	return nil
}
func (m *CredentialBindings) Down() error { return nil } // Retain security history on rollback.
