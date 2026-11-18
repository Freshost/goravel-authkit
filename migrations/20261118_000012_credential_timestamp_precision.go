package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

// CredentialTimestampPrecision upgrades existing whole-second credential
// timestamps so password changes and credential issuance remain distinguishable.
type CredentialTimestampPrecision struct {
	table     string
	column    string
	signature string
}

func (r *CredentialTimestampPrecision) Signature() string { return r.signature }

func (r *CredentialTimestampPrecision) Up() error {
	conn := facades.Schema().GetConnection()
	if facades.Config().GetString("database.connections."+conn+".driver") == "sqlite" {
		// SQLite stores timestamp text without a declared fractional precision.
		return nil
	}
	if !facades.Schema().HasColumn(r.table, r.column) {
		return nil
	}
	return facades.Schema().Table(r.table, func(t schema.Blueprint) {
		t.TimestampTz(r.column, 6).UseCurrent().Change()
	})
}

func (r *CredentialTimestampPrecision) Down() error {
	// Retain precision on rollback: truncation would destroy credential ordering.
	return nil
}
