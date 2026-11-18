package migrations

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestCredentialBindingSignaturesFollowTheirOwnTables(t *testing.T) {
	signatures := func(remember string) []string {
		var result []string
		for _, migration := range ForTables(MigrationConfig{UsersTable: "accounts", RememberTokensTable: remember}) {
			result = append(result, migration.Signature())
		}
		return result
	}
	first, second := signatures("remember_a"), signatures("remember_b")
	require.Contains(t, first, "authkit_accounts_two_factor_version")
	require.Contains(t, second, "authkit_accounts_two_factor_version")
	require.Contains(t, first, "authkit_remember_a_credential_bindings")
	require.Contains(t, second, "authkit_remember_b_credential_bindings")
	require.NotContains(t, second, "authkit_remember_a_credential_bindings")
}
