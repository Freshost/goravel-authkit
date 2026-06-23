package services

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// adminRoles is the management-role set used by the user-management tests.
var adminRoles = []string{"admin"}

func newUsersSvc(repo *fakeRepo, roles []string) *Users {
	return NewUsers(repo, fakeHasher{}, 8, roles, adminRoles)
}

func TestUsersCreate_DefaultsToNonAdminRole(t *testing.T) {
	repo := newFakeRepo()
	// roles configured as [admin, user]: the default must skip admin and pick user.
	svc := newUsersSvc(repo, []string{"admin", "user"})

	u, err := svc.Create(context.Background(), "New@Example.com", "  New User ", "secret123", "")
	require.NoError(t, err)
	assert.Equal(t, "new@example.com", u.Email)
	require.NotNil(t, u.Name)
	assert.Equal(t, "New User", *u.Name)
	assert.Equal(t, "user", u.Role, "must never silently default to admin")
	assert.NotEqual(t, "admin", u.Role)
	require.NotNil(t, u.PasswordHash)
	assert.Equal(t, "hash:secret123", *u.PasswordHash)
}

func TestUsersCreate_NoRolesConfiguredDefaultsToUser(t *testing.T) {
	repo := newFakeRepo()
	svc := newUsersSvc(repo, nil)

	u, err := svc.Create(context.Background(), "x@example.com", "", "secret123", "")
	require.NoError(t, err)
	assert.Equal(t, DefaultRole, u.Role)
	assert.Equal(t, "user", u.Role)
}

func TestUsersCreate_RejectsRoleOutsideAllowList(t *testing.T) {
	repo := newFakeRepo()
	svc := newUsersSvc(repo, []string{"admin", "user"})

	_, err := svc.Create(context.Background(), "x@example.com", "", "secret123", "superuser")
	assert.ErrorIs(t, err, ErrValidation)
}

func TestUsersCreate_DuplicateAndPasswordRules(t *testing.T) {
	repo := newFakeRepo()
	seedUser(repo, "admin@example.com", "secret123")
	svc := newUsersSvc(repo, nil)

	_, err := svc.Create(context.Background(), "admin@example.com", "", "secret123", "")
	assert.ErrorIs(t, err, ErrAlreadyExists)

	_, err = svc.Create(context.Background(), "fresh@example.com", "", "short", "")
	assert.ErrorIs(t, err, ErrValidation, "too short")

	// All-whitespace password rejected.
	_, err = svc.Create(context.Background(), "ws@example.com", "", "          ", "")
	assert.ErrorIs(t, err, ErrValidation, "all-whitespace")

	// Over the 72-byte bcrypt limit rejected.
	_, err = svc.Create(context.Background(), "long@example.com", "", strings.Repeat("a", MaxPasswordBytes+1), "")
	assert.ErrorIs(t, err, ErrValidation, "too long")
}

func TestUsersDelete_LastAdminGuarded(t *testing.T) {
	repo := newFakeRepo()
	u := seedUser(repo, "only@example.com", "secret123") // role admin
	svc := newUsersSvc(repo, nil)

	err := svc.Delete(context.Background(), u.ID)
	assert.ErrorIs(t, err, ErrLastAdmin)
}

func TestUsersDelete_RefusesLastAdminEvenWithOtherNonAdmins(t *testing.T) {
	repo := newFakeRepo()
	admin := seedUser(repo, "admin@example.com", "secret123") // admin
	member := seedUser(repo, "member@example.com", "secret123")
	member.Role = "user"
	repo.seed(member)
	svc := newUsersSvc(repo, []string{"admin", "user"})

	// Deleting the only admin is refused even though another (non-admin) row exists.
	err := svc.Delete(context.Background(), admin.ID)
	assert.ErrorIs(t, err, ErrLastAdmin)

	// A non-admin can be deleted freely.
	require.NoError(t, svc.Delete(context.Background(), member.ID))
}

func TestUsersDelete_WithOtherAdminSucceeds(t *testing.T) {
	repo := newFakeRepo()
	a := seedUser(repo, "a@example.com", "secret123")
	seedUser(repo, "b@example.com", "secret123")
	svc := newUsersSvc(repo, nil)

	require.NoError(t, svc.Delete(context.Background(), a.ID))
	_, ok := repo.byID[a.ID]
	assert.False(t, ok)
}

func TestUsersUpdate_EmailCollision(t *testing.T) {
	repo := newFakeRepo()
	seedUser(repo, "taken@example.com", "secret123")
	b := seedUser(repo, "b@example.com", "secret123")
	svc := newUsersSvc(repo, nil)

	_, err := svc.Update(context.Background(), b.ID, "taken@example.com", "B", "admin", nil, uuid.Nil)
	assert.ErrorIs(t, err, ErrAlreadyExists)
}

func TestUsersUpdate_DisableAndEnable(t *testing.T) {
	repo := newFakeRepo()
	admin := seedUser(repo, "admin@example.com", "secret123")
	// A second active admin so disabling the first is allowed.
	seedUser(repo, "admin2@example.com", "secret123")
	svc := newUsersSvc(repo, nil)

	disabled := true
	got, err := svc.Update(context.Background(), admin.ID, "admin@example.com", "Admin", "admin", &disabled, uuid.Nil)
	require.NoError(t, err)
	assert.True(t, got.IsDisabled())

	enabled := false
	got, err = svc.Update(context.Background(), admin.ID, "admin@example.com", "Admin", "admin", &enabled, uuid.Nil)
	require.NoError(t, err)
	assert.False(t, got.IsDisabled())
}

func TestUsersUpdate_RefusesDisablingLastAdmin(t *testing.T) {
	repo := newFakeRepo()
	admin := seedUser(repo, "admin@example.com", "secret123")
	svc := newUsersSvc(repo, nil)

	disabled := true
	_, err := svc.Update(context.Background(), admin.ID, "admin@example.com", "Admin", "admin", &disabled, uuid.Nil)
	assert.ErrorIs(t, err, ErrLastAdmin)
}

func TestUsersUpdate_RefusesDemotingLastAdmin(t *testing.T) {
	repo := newFakeRepo()
	admin := seedUser(repo, "admin@example.com", "secret123")
	svc := newUsersSvc(repo, []string{"admin", "user"})

	// Demote admin -> user with no other admin remaining: refused.
	_, err := svc.Update(context.Background(), admin.ID, "admin@example.com", "Admin", "user", nil, uuid.Nil)
	assert.ErrorIs(t, err, ErrLastAdmin)
}

func TestUsersUpdate_DemoteAdminWithAnotherAdminSucceeds(t *testing.T) {
	repo := newFakeRepo()
	admin := seedUser(repo, "admin@example.com", "secret123")
	seedUser(repo, "admin2@example.com", "secret123")
	svc := newUsersSvc(repo, []string{"admin", "user"})

	got, err := svc.Update(context.Background(), admin.ID, "admin@example.com", "Admin", "user", nil, uuid.Nil)
	require.NoError(t, err)
	assert.Equal(t, "user", got.Role)
}

func TestUsersUpdate_RefusesSelfDisable(t *testing.T) {
	repo := newFakeRepo()
	admin := seedUser(repo, "admin@example.com", "secret123")
	seedUser(repo, "admin2@example.com", "secret123") // another admin remains
	svc := newUsersSvc(repo, nil)

	disabled := true
	_, err := svc.Update(context.Background(), admin.ID, "admin@example.com", "Admin", "admin", &disabled, admin.ID)
	assert.ErrorIs(t, err, ErrValidation, "cannot self-disable even when other admins exist")
}

func TestUsersSetPassword_BumpsTimestampAndValidates(t *testing.T) {
	repo := newFakeRepo()
	u := seedUser(repo, "admin@example.com", "secret123")
	old := u.PasswordChangedAt
	svc := newUsersSvc(repo, nil)

	got, err := svc.SetPassword(context.Background(), u.ID, "newsecret456")
	require.NoError(t, err)
	assert.True(t, got.PasswordChangedAt.After(old))
	assert.Equal(t, "hash:newsecret456", *repo.byID[u.ID].PasswordHash)

	_, err = svc.SetPassword(context.Background(), u.ID, "          ")
	assert.ErrorIs(t, err, ErrValidation, "all-whitespace rejected")

	_, err = svc.SetPassword(context.Background(), u.ID, strings.Repeat("a", MaxPasswordBytes+1))
	assert.ErrorIs(t, err, ErrValidation, "too long rejected")
}

func TestUsersGetByID_NotFound(t *testing.T) {
	svc := newUsersSvc(newFakeRepo(), nil)
	_, err := svc.GetByID(context.Background(), seedUser(newFakeRepo(), "x@example.com", "secret123").ID)
	assert.ErrorIs(t, err, ErrNotFound)
}
