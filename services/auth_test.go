package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/freshost/goravel-auth/models"
)

func seedUser(repo *fakeRepo, email, password string) *models.User {
	u := &models.User{
		ID:                uuid.New(),
		Email:             email,
		PasswordHash:      ptr("hash:" + password),
		PasswordChangedAt: time.Now().Add(-time.Hour).UTC(),
		Role:              "admin",
	}
	repo.seed(u)
	return u
}

func TestAuthenticate_Success(t *testing.T) {
	repo := newFakeRepo()
	u := seedUser(repo, "admin@example.com", "secret123")
	svc := NewAuth(repo, fakeHasher{}, 8)

	got, err := svc.Authenticate(context.Background(), "  Admin@Example.com ", "secret123")
	require.NoError(t, err)
	assert.Equal(t, u.ID, got.ID)
}

func TestAuthenticate_WrongPasswordAndUnknownEmailBothInvalid(t *testing.T) {
	repo := newFakeRepo()
	seedUser(repo, "admin@example.com", "secret123")
	svc := NewAuth(repo, fakeHasher{}, 8)

	_, err := svc.Authenticate(context.Background(), "admin@example.com", "wrong")
	assert.ErrorIs(t, err, ErrInvalidCredentials)

	_, err = svc.Authenticate(context.Background(), "nobody@example.com", "whatever")
	assert.ErrorIs(t, err, ErrInvalidCredentials)
}

func TestAuthenticate_EmptyCredentials(t *testing.T) {
	svc := NewAuth(newFakeRepo(), fakeHasher{}, 8)
	_, err := svc.Authenticate(context.Background(), "", "")
	assert.ErrorIs(t, err, ErrInvalidCredentials)
}

func TestChangePassword_Success(t *testing.T) {
	repo := newFakeRepo()
	u := seedUser(repo, "admin@example.com", "secret123")
	svc := NewAuth(repo, fakeHasher{}, 8)

	changedAt, err := svc.ChangePassword(context.Background(), u.ID, "secret123", "newsecret456")
	require.NoError(t, err)
	assert.True(t, changedAt.After(u.PasswordChangedAt))
	assert.Equal(t, "hash:newsecret456", *repo.byID[u.ID].PasswordHash)
}

func TestChangePassword_WrongCurrent(t *testing.T) {
	repo := newFakeRepo()
	u := seedUser(repo, "admin@example.com", "secret123")
	svc := NewAuth(repo, fakeHasher{}, 8)

	_, err := svc.ChangePassword(context.Background(), u.ID, "bad", "newsecret456")
	assert.ErrorIs(t, err, ErrWrongPassword)
}

func TestChangePassword_TooShortAndUnchanged(t *testing.T) {
	repo := newFakeRepo()
	u := seedUser(repo, "admin@example.com", "secret123")
	svc := NewAuth(repo, fakeHasher{}, 8)

	_, err := svc.ChangePassword(context.Background(), u.ID, "secret123", "short")
	assert.ErrorIs(t, err, ErrValidation)

	_, err = svc.ChangePassword(context.Background(), u.ID, "secret123", "secret123")
	assert.ErrorIs(t, err, ErrValidation)
}

func TestMe_MissingUserUnauthorized(t *testing.T) {
	svc := NewAuth(newFakeRepo(), fakeHasher{}, 8)
	_, err := svc.Me(context.Background(), uuid.New())
	assert.ErrorIs(t, err, ErrUnauthorized)
}

func TestMe_RepoErrorWrapsInternal(t *testing.T) {
	repo := newFakeRepo()
	repo.failOp = true
	svc := NewAuth(repo, fakeHasher{}, 8)
	_, err := svc.Me(context.Background(), uuid.New())
	assert.True(t, errors.Is(err, ErrInternal))
}
