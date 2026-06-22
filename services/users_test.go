package services

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUsersCreate_DefaultsRoleAndHashes(t *testing.T) {
	repo := newFakeRepo()
	svc := NewUsers(repo, fakeHasher{}, 8, nil)

	u, err := svc.Create(context.Background(), "New@Example.com", "  New Admin ", "secret123", "")
	require.NoError(t, err)
	assert.Equal(t, "new@example.com", u.Email)
	require.NotNil(t, u.Name)
	assert.Equal(t, "New Admin", *u.Name)
	assert.Equal(t, DefaultRole, u.Role)
	require.NotNil(t, u.PasswordHash)
	assert.Equal(t, "hash:secret123", *u.PasswordHash)
}

func TestUsersCreate_DuplicateAndShortPassword(t *testing.T) {
	repo := newFakeRepo()
	seedUser(repo, "admin@example.com", "secret123")
	svc := NewUsers(repo, fakeHasher{}, 8, nil)

	_, err := svc.Create(context.Background(), "admin@example.com", "", "secret123", "")
	assert.ErrorIs(t, err, ErrAlreadyExists)

	_, err = svc.Create(context.Background(), "fresh@example.com", "", "short", "")
	assert.ErrorIs(t, err, ErrValidation)
}

func TestUsersDelete_LastAdminGuarded(t *testing.T) {
	repo := newFakeRepo()
	u := seedUser(repo, "only@example.com", "secret123")
	svc := NewUsers(repo, fakeHasher{}, 8, nil)

	err := svc.Delete(context.Background(), u.ID)
	assert.ErrorIs(t, err, ErrLastAdmin)
}

func TestUsersDelete_WithOthersSucceeds(t *testing.T) {
	repo := newFakeRepo()
	a := seedUser(repo, "a@example.com", "secret123")
	seedUser(repo, "b@example.com", "secret123")
	svc := NewUsers(repo, fakeHasher{}, 8, nil)

	require.NoError(t, svc.Delete(context.Background(), a.ID))
	_, ok := repo.byID[a.ID]
	assert.False(t, ok)
}

func TestUsersUpdate_EmailCollision(t *testing.T) {
	repo := newFakeRepo()
	seedUser(repo, "taken@example.com", "secret123")
	b := seedUser(repo, "b@example.com", "secret123")
	svc := NewUsers(repo, fakeHasher{}, 8, nil)

	_, err := svc.Update(context.Background(), b.ID, "taken@example.com", "B", "admin", nil)
	assert.ErrorIs(t, err, ErrAlreadyExists)
}

func TestUsersUpdate_DisableAndEnable(t *testing.T) {
	repo := newFakeRepo()
	u := seedUser(repo, "admin@example.com", "secret123")
	svc := NewUsers(repo, fakeHasher{}, 8, nil)

	disabled := true
	got, err := svc.Update(context.Background(), u.ID, "admin@example.com", "Admin", "admin", &disabled)
	require.NoError(t, err)
	assert.True(t, got.IsDisabled())

	enabled := false
	got, err = svc.Update(context.Background(), u.ID, "admin@example.com", "Admin", "admin", &enabled)
	require.NoError(t, err)
	assert.False(t, got.IsDisabled())
}

func TestUsersSetPassword_BumpsTimestamp(t *testing.T) {
	repo := newFakeRepo()
	u := seedUser(repo, "admin@example.com", "secret123")
	old := u.PasswordChangedAt
	svc := NewUsers(repo, fakeHasher{}, 8, nil)

	got, err := svc.SetPassword(context.Background(), u.ID, "newsecret456")
	require.NoError(t, err)
	assert.True(t, got.PasswordChangedAt.After(old))
	assert.Equal(t, "hash:newsecret456", *repo.byID[u.ID].PasswordHash)
}

func TestUsersGetByID_NotFound(t *testing.T) {
	svc := NewUsers(newFakeRepo(), fakeHasher{}, 8, nil)
	_, err := svc.GetByID(context.Background(), seedUser(newFakeRepo(), "x@example.com", "secret123").ID)
	assert.ErrorIs(t, err, ErrNotFound)
}
