package services

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/freshost/goravel-authkit/models"
)

type fakeAPITokensRepo struct {
	tokens map[uuid.UUID]*models.APIToken
}

func newFakeAPITokensRepo() *fakeAPITokensRepo {
	return &fakeAPITokensRepo{tokens: map[uuid.UUID]*models.APIToken{}}
}

func (f *fakeAPITokensRepo) Create(_ context.Context, token *models.APIToken) error {
	cp := *token
	f.tokens[token.ID] = &cp
	return nil
}

func (f *fakeAPITokensRepo) FindBySelector(_ context.Context, selector string) (*models.APIToken, error) {
	for _, token := range f.tokens {
		if token.Selector == selector {
			cp := *token
			return &cp, nil
		}
	}
	return nil, nil
}

func (f *fakeAPITokensRepo) ListByUser(_ context.Context, userID uuid.UUID) ([]models.APIToken, error) {
	var out []models.APIToken
	for _, token := range f.tokens {
		if token.UserID == userID && token.RevokedAt == nil {
			out = append(out, *token)
		}
	}
	return out, nil
}

func (f *fakeAPITokensRepo) CountActiveByUser(_ context.Context, userID uuid.UUID, now time.Time) (int64, error) {
	var count int64
	for _, token := range f.tokens {
		if token.UserID == userID && token.Active(now) {
			count++
		}
	}
	return count, nil
}

func (f *fakeAPITokensRepo) Revoke(_ context.Context, id, userID uuid.UUID, now time.Time) (int64, error) {
	token := f.tokens[id]
	if token == nil || token.UserID != userID || token.RevokedAt != nil {
		return 0, nil
	}
	token.RevokedAt = &now
	return 1, nil
}

func (f *fakeAPITokensRepo) RevokeAllByUser(_ context.Context, userID uuid.UUID, now time.Time) error {
	for _, token := range f.tokens {
		if token.UserID == userID && token.RevokedAt == nil {
			t := now
			token.RevokedAt = &t
		}
	}
	return nil
}

func (f *fakeAPITokensRepo) TouchLastUsed(_ context.Context, id uuid.UUID, _ time.Time, now time.Time) error {
	if token := f.tokens[id]; token != nil {
		token.LastUsedAt = &now
	}
	return nil
}

func (f *fakeAPITokensRepo) DeletePrunable(_ context.Context, before time.Time) error {
	for id, token := range f.tokens {
		if token.ExpiresAt.Before(before) || (token.RevokedAt != nil && token.RevokedAt.Before(before)) {
			delete(f.tokens, id)
		}
	}
	return nil
}

func newAPITokenTestService(t *testing.T, max int) (*APITokens, *fakeAPITokensRepo, *models.User, time.Time) {
	t.Helper()
	users := newFakeRepo()
	user := seedUser(users, "token@example.com", "secret123")
	tokens := newFakeAPITokensRepo()
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	svc := NewAPITokens(tokens, users, fakeHasher{}, nil, []string{"projects:read", "projects:write"}, 90*24*time.Hour, max)
	svc.now = func() time.Time { return now }
	return svc, tokens, user, now
}

func TestAPITokensIssueAndResolve(t *testing.T) {
	svc, repo, user, now := newAPITokenTestService(t, 20)
	issued, err := svc.Issue(context.Background(), IssueAPITokenCommand{
		UserID: user.ID, Name: " Deployment CLI ", ExpiresAt: now.Add(24 * time.Hour),
		Scopes: []string{"projects:write", "projects:read", "projects:read"}, Password: "secret123",
	})
	require.NoError(t, err)
	assert.Equal(t, "Deployment CLI", issued.Token.Name)
	assert.Equal(t, []string{"projects:read", "projects:write"}, []string(issued.Token.Scopes))
	assert.Contains(t, issued.Plaintext, "gak_")
	assert.NotContains(t, issued.Token.ValidatorHash, issued.Plaintext)

	resolved, err := svc.Resolve(context.Background(), issued.Plaintext)
	require.NoError(t, err)
	assert.Equal(t, issued.Token.ID, resolved.ID)
	assert.NotNil(t, repo.tokens[issued.Token.ID].LastUsedAt)
}

func TestAPITokensRejectInvalidInputAndCredentials(t *testing.T) {
	svc, _, user, now := newAPITokenTestService(t, 20)
	base := IssueAPITokenCommand{UserID: user.ID, Name: "CLI", ExpiresAt: now.Add(time.Hour), Scopes: []string{"projects:read"}, Password: "secret123"}

	cmd := base
	cmd.Name = " "
	_, err := svc.Issue(context.Background(), cmd)
	assert.ErrorIs(t, err, ErrValidation)

	cmd = base
	cmd.Scopes = []string{"admin:anything"}
	_, err = svc.Issue(context.Background(), cmd)
	assert.ErrorIs(t, err, ErrValidation)

	cmd = base
	cmd.Password = "wrong"
	_, err = svc.Issue(context.Background(), cmd)
	assert.ErrorIs(t, err, ErrWrongPassword)

	cmd = base
	cmd.ExpiresAt = now.Add(91 * 24 * time.Hour)
	_, err = svc.Issue(context.Background(), cmd)
	assert.ErrorIs(t, err, ErrValidation)
}

func TestAPITokensLimitRevokeAndExpired(t *testing.T) {
	svc, _, user, now := newAPITokenTestService(t, 1)
	issued, err := svc.Issue(context.Background(), IssueAPITokenCommand{UserID: user.ID, Name: "CLI", ExpiresAt: now.Add(time.Hour), Password: "secret123"})
	require.NoError(t, err)

	_, err = svc.Issue(context.Background(), IssueAPITokenCommand{UserID: user.ID, Name: "Other", ExpiresAt: now.Add(time.Hour), Password: "secret123"})
	assert.ErrorIs(t, err, ErrTokenLimit)

	require.NoError(t, svc.Revoke(context.Background(), user.ID, issued.Token.ID))
	_, err = svc.Resolve(context.Background(), issued.Plaintext)
	assert.ErrorIs(t, err, ErrInvalidAPIToken)

	svc.now = func() time.Time { return now.Add(2 * time.Hour) }
	_, err = svc.Resolve(context.Background(), issued.Plaintext)
	assert.ErrorIs(t, err, ErrInvalidAPIToken)
}

func TestAPITokensNeverCrossUsers(t *testing.T) {
	svc, _, user, now := newAPITokenTestService(t, 20)
	issued, err := svc.Issue(context.Background(), IssueAPITokenCommand{UserID: user.ID, Name: "CLI", ExpiresAt: now.Add(time.Hour), Password: "secret123"})
	require.NoError(t, err)

	err = svc.Revoke(context.Background(), uuid.New(), issued.Token.ID)
	assert.ErrorIs(t, err, ErrNotFound)

	_, err = svc.Resolve(context.Background(), "gak_invalid.invalid")
	assert.ErrorIs(t, err, ErrInvalidAPIToken)
}
