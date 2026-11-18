package services

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/freshost/goravel-authkit/contracts"
)

func TestAPITokensImpersonatedCreation(t *testing.T) {
	svc, tokens, target, now := newAPITokenTestService(t, 1)
	users := svc.users.(*fakeRepo)
	actor := seedUser(users, "admin@example.com", "admin-secret")
	users.byID[actor.ID].Role = "admin"
	users.byID[target.ID].Role = "user"
	secret := "target-totp-secret"
	users.byID[target.ID].TwoFactorSecret = &secret
	users.byID[target.ID].TwoFactorConfirmedAt = &now
	svc.AllowImpersonatedCreation("admin", map[string]APITokenDelegationGuard{
		"admin": {Users: users, Policy: NewImpersonation([]string{"admin"}, []string{"admin"}, []string{"admin"})},
	})
	cmd := IssueAPITokenCommand{UserID: target.ID, Name: "Support CLI", ExpiresAt: now.Add(time.Hour), Scopes: []string{"projects:read"}}

	// Direct login must still verify both credentials.
	_, err := svc.Issue(context.Background(), cmd)
	assert.ErrorIs(t, err, ErrWrongPassword)
	cmd.Password = "secret123"
	_, err = svc.Issue(context.Background(), cmd)
	assert.ErrorIs(t, err, ErrInvalidCode)
	cmd.Password = ""

	issued, err := svc.IssueImpersonated(context.Background(), "admin", actor.ID, cmd)
	require.NoError(t, err)
	assert.Equal(t, target.ID, issued.Token.UserID)
	require.NotNil(t, issued.DelegatedBy)
	assert.Equal(t, actor.ID, issued.DelegatedBy.UserID)
	assert.Equal(t, actor.Email, issued.DelegatedBy.Email)
	assert.Len(t, tokens.tokens, 1)
	_, err = svc.IssueImpersonated(context.Background(), "admin", actor.ID, cmd)
	assert.ErrorIs(t, err, ErrTokenLimit)
}

func TestAPITokensImpersonationRevalidatesAuthority(t *testing.T) {
	for _, change := range []string{"disabled actor", "deleted actor", "demoted actor", "protected target", "disabled target", "unknown guard", "disabled feature", "denied host policy"} {
		t.Run(change, func(t *testing.T) {
			svc, tokens, target, now := newAPITokenTestService(t, 20)
			users := svc.users.(*fakeRepo)
			actor := seedUser(users, "admin@example.com", "admin-secret")
			users.byID[actor.ID].Role = "admin"
			users.byID[target.ID].Role = "user"
			svc.AllowImpersonatedCreation("client", map[string]APITokenDelegationGuard{
				"admin": {Users: users, Policy: NewImpersonation([]string{"admin"}, []string{"client"}, []string{"admin"})},
			})
			guard := "admin"
			want := ErrForbidden
			switch change {
			case "disabled actor":
				users.byID[actor.ID].DisabledAt = &now
			case "deleted actor":
				delete(users.byID, actor.ID)
			case "demoted actor":
				users.byID[actor.ID].Role = "user"
			case "protected target":
				users.byID[target.ID].Role = "admin"
			case "disabled target":
				users.byID[target.ID].DisabledAt = &now
				want = ErrUnauthorized
			case "unknown guard":
				guard = "unknown"
			case "disabled feature":
				svc.delegationActors = nil
			case "denied host policy":
				contracts.SetImpersonationPolicy(denyAPITokenDelegation{})
				t.Cleanup(func() { contracts.SetImpersonationPolicy(nil) })
			}
			_, err := svc.IssueImpersonated(context.Background(), guard, actor.ID, IssueAPITokenCommand{UserID: target.ID, Name: "CLI", ExpiresAt: now.Add(time.Hour)})
			assert.ErrorIs(t, err, want)
			assert.Empty(t, tokens.tokens)
		})
	}
}

func TestAPITokensDelegationUsesActorGuardPolicy(t *testing.T) {
	svc, _, target, now := newAPITokenTestService(t, 20)
	actors := newFakeRepo()
	actor := seedUser(actors, "admin@example.com", "admin-secret")
	actors.byID[actor.ID].Role = "admin"
	svc.AllowImpersonatedCreation("client", map[string]APITokenDelegationGuard{
		"admin": {Users: actors, Policy: NewImpersonation([]string{"admin"}, []string{"client"}, nil)},
	})
	issued, err := svc.IssueImpersonated(context.Background(), "admin", actor.ID, IssueAPITokenCommand{UserID: target.ID, Name: "CLI", ExpiresAt: now.Add(time.Hour)})
	require.NoError(t, err)
	assert.Equal(t, target.ID, issued.Token.UserID)
	assert.Equal(t, "admin", issued.DelegatedBy.Guard)
	_, err = svc.IssueImpersonated(context.Background(), "client", uuid.New(), IssueAPITokenCommand{})
	assert.ErrorIs(t, err, ErrForbidden)
}

type denyAPITokenDelegation struct{}

func (denyAPITokenDelegation) CanImpersonate(context.Context, contracts.Principal, string, contracts.Principal) (bool, error) {
	return false, nil
}
