package oidc

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

// Migrations is registered only when the provider is enabled. Hosts owning
// migration registration may explicitly include it alongside Authkit migrations.
func Migrations() []schema.Migration { return []schema.Migration{&providerMigration{}} }

type providerMigration struct{}

func (*providerMigration) Signature() string { return "authkit_oidc_provider_20261118" }
func (*providerMigration) Up() error {
	s := facades.Schema()
	if !s.HasTable(clientsTable) {
		if err := s.Create(clientsTable, func(t schema.Blueprint) {
			t.String("id", 200)
			t.String("issuer", 512)
			t.Primary("id", "issuer")
			t.String("name", 200)
			t.String("application_type", 20)
			t.String("auth_method", 40)
			t.Text("secret_hash")
			t.Jsonb("redirect_uris")
			t.Jsonb("scopes")
			t.Jsonb("audience")
			t.Boolean("allow_refresh")
			t.Boolean("skip_consent")
			t.Boolean("disabled")
			t.BigInteger("version")
		}); err != nil {
			return err
		}
	}
	if !s.HasTable(requestsTable) {
		if err := s.Create(requestsTable, func(t schema.Blueprint) {
			t.String("id", 64)
			t.Primary("id")
			t.String("issuer", 512)
			t.String("client_id", 200)
			t.BigInteger("client_version")
			t.Text("payload")
			t.String("binding_hash", 64)
			t.String("initial_event", 64)
			t.String("hint_subject", 200)
			t.Uuid("consent_user_id")
			t.String("consent_event", 64)
			t.String("consent_hash", 64)
			t.Uuid("user_id")
			t.TimestampTz("credential_stamp")
			t.String("two_factor_stamp", 64)
			t.TimestampTz("auth_time")
			t.Jsonb("amr")
			t.Jsonb("scopes")
			t.Jsonb("audience")
			t.Boolean("approved")
			t.String("code_hash", 64).Nullable()
			t.Unique("code_hash")
			t.TimestampTz("code_expires_at").Nullable()
			t.TimestampTz("consumed_at").Nullable()
			t.String("grant_id", 64)
			t.TimestampTz("created_at")
			t.TimestampTz("expires_at")
			t.Index("expires_at")
		}); err != nil {
			return err
		}
	}
	if !s.HasTable(grantsTable) {
		if err := s.Create(grantsTable, func(t schema.Blueprint) {
			t.String("id", 64)
			t.Primary("id")
			t.String("issuer", 512)
			t.String("client_id", 200)
			t.BigInteger("client_version")
			t.Uuid("user_id")
			t.TimestampTz("credential_stamp")
			t.String("two_factor_stamp", 64)
			t.TimestampTz("auth_time")
			t.Jsonb("amr")
			t.Jsonb("scopes")
			t.Jsonb("audience")
			t.TimestampTz("created_at")
			t.TimestampTz("expires_at")
			t.TimestampTz("revoked_at").Nullable()
			t.Index("issuer", "user_id")
			t.Index("expires_at")
		}); err != nil {
			return err
		}
	}
	if !s.HasTable(tokensTable) {
		return s.Create(tokensTable, func(t schema.Blueprint) {
			t.String("id", 64)
			t.Primary("id")
			t.String("issuer", 512)
			t.String("grant_id", 64)
			t.String("kind", 20)
			t.String("hash", 64).Nullable()
			t.Unique("hash")
			t.Jsonb("scopes")
			t.TimestampTz("created_at")
			t.TimestampTz("expires_at")
			t.TimestampTz("consumed_at").Nullable()
			t.Index("grant_id")
			t.Index("expires_at")
		})
	}
	return nil
}
func (*providerMigration) Down() error {
	for _, table := range []string{tokensTable, requestsTable, grantsTable, clientsTable} {
		if err := facades.Schema().DropIfExists(table); err != nil {
			return err
		}
	}
	return nil
}
