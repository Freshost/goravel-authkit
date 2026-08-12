package migrations

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

// AddAuditLoginIndex keeps the paginated administrator sign-in overview fast
// as the audit table grows.
type AddAuditLoginIndex struct {
	table     string
	signature string
}

func (r *AddAuditLoginIndex) Signature() string { return r.signature }

func (r *AddAuditLoginIndex) indexName() string {
	sum := sha256.Sum256([]byte(r.table))
	return "authkit_login_events_" + hex.EncodeToString(sum[:6])
}

func (r *AddAuditLoginIndex) Up() error {
	if !facades.Schema().HasTable(r.table) || facades.Schema().HasIndex(r.table, r.indexName()) {
		return nil
	}
	return facades.Schema().Table(r.table, func(table schema.Blueprint) {
		table.Index("action", "created_at").Name(r.indexName())
	})
}

func (r *AddAuditLoginIndex) Down() error {
	if !facades.Schema().HasTable(r.table) || !facades.Schema().HasIndex(r.table, r.indexName()) {
		return nil
	}
	return facades.Schema().Table(r.table, func(table schema.Blueprint) {
		table.DropIndexByName(r.indexName())
	})
}
