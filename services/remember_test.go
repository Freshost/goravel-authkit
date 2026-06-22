package services

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/freshost/goravel-authkit/models"
)

// fakeRememberRepo is an in-memory RememberRepository for service unit tests.
type fakeRememberRepo struct {
	byID map[uuid.UUID]*models.RememberToken
}

func newFakeRememberRepo() *fakeRememberRepo {
	return &fakeRememberRepo{byID: map[uuid.UUID]*models.RememberToken{}}
}

func (f *fakeRememberRepo) Create(_ context.Context, t *models.RememberToken) error {
	cp := *t
	f.byID[t.ID] = &cp
	return nil
}

func (f *fakeRememberRepo) FindBySelector(_ context.Context, selector string) (*models.RememberToken, error) {
	for _, t := range f.byID {
		if t.Selector == selector {
			cp := *t
			return &cp, nil
		}
	}
	return nil, nil
}

func (f *fakeRememberRepo) RotateValidator(_ context.Context, id uuid.UUID, expectedCurrentHash, newCurrentHash, newPreviousHash string, rotatedAt, expiresAt time.Time) (int64, error) {
	t, ok := f.byID[id]
	if !ok || t.ValidatorHash != expectedCurrentHash {
		return 0, nil
	}
	t.ValidatorHash = newCurrentHash
	t.PreviousValidatorHash = newPreviousHash
	t.RotatedAt = &rotatedAt
	t.ExpiresAt = expiresAt
	return 1, nil
}

func (f *fakeRememberRepo) Delete(_ context.Context, id uuid.UUID) error {
	delete(f.byID, id)
	return nil
}

func (f *fakeRememberRepo) DeleteByUser(_ context.Context, userID uuid.UUID) error {
	for id, t := range f.byID {
		if t.UserID == userID {
			delete(f.byID, id)
		}
	}
	return nil
}

func (f *fakeRememberRepo) DeleteExpired(_ context.Context, now time.Time) error {
	for id, t := range f.byID {
		if t.ExpiresAt.Before(now) {
			delete(f.byID, id)
		}
	}
	return nil
}

func TestRemember_IssueAndResolveRotates(t *testing.T) {
	repo := newFakeRememberRepo()
	svc := NewRemember(repo, time.Hour)
	uid := uuid.New()

	cookie, err := svc.Issue(context.Background(), uid)
	require.NoError(t, err)
	assert.Contains(t, cookie, ":")

	gotUID, rotated, err := svc.Resolve(context.Background(), cookie)
	require.NoError(t, err)
	assert.Equal(t, uid, gotUID)
	assert.NotEmpty(t, rotated, "a fresh cookie should be issued on rotation")
	assert.NotEqual(t, cookie, rotated, "validator should rotate on use")
	assert.Equal(t, selectorOf(cookie), selectorOf(rotated), "selector stays stable")

	// The rotated (current) cookie validates and rotates again.
	_, rotated2, err := svc.Resolve(context.Background(), rotated)
	require.NoError(t, err)
	assert.NotEmpty(t, rotated2)
}

func TestRemember_SupersededValidatorWithinGraceAccepted(t *testing.T) {
	repo := newFakeRememberRepo()
	svc := NewRemember(repo, time.Hour)
	uid := uuid.New()

	cookie, err := svc.Issue(context.Background(), uid)
	require.NoError(t, err)
	// First use rotates: `cookie` becomes the previous validator (RotatedAt=now).
	_, _, err = svc.Resolve(context.Background(), cookie)
	require.NoError(t, err)

	// A concurrent request still carrying the original cookie is accepted within
	// the grace window — not treated as theft — and issues no new cookie.
	gotUID, fresh, err := svc.Resolve(context.Background(), cookie)
	require.NoError(t, err)
	assert.Equal(t, uid, gotUID)
	assert.Empty(t, fresh, "grace acceptance must not overwrite the rotated cookie")
	assert.NotEmpty(t, repo.byID, "the token family must survive a concurrent request")
}

func TestRemember_SupersededValidatorAfterGraceIsTheft(t *testing.T) {
	repo := newFakeRememberRepo()
	svc := NewRemember(repo, time.Hour)
	uid := uuid.New()

	cookie, err := svc.Issue(context.Background(), uid)
	require.NoError(t, err)
	_, _, err = svc.Resolve(context.Background(), cookie)
	require.NoError(t, err)

	// Push the rotation into the past, beyond the grace window.
	for _, tk := range repo.byID {
		old := time.Now().Add(-10 * time.Minute)
		tk.RotatedAt = &old
	}

	// The original (now long-superseded) validator is treated as theft.
	_, _, err = svc.Resolve(context.Background(), cookie)
	assert.ErrorIs(t, err, ErrInvalidRememberToken)
	assert.Empty(t, repo.byID, "stale-beyond-grace reuse revokes the whole family")
}

func TestRemember_ResolveUnknownSelector(t *testing.T) {
	svc := NewRemember(newFakeRememberRepo(), time.Hour)
	_, _, err := svc.Resolve(context.Background(), "nosuch:validator")
	assert.ErrorIs(t, err, ErrInvalidRememberToken)
}

func TestRemember_ResolveMalformed(t *testing.T) {
	svc := NewRemember(newFakeRememberRepo(), time.Hour)
	for _, bad := range []string{"", "noseparator", ":onlyvalidator", "onlyselector:"} {
		_, _, err := svc.Resolve(context.Background(), bad)
		assert.ErrorIs(t, err, ErrInvalidRememberToken, "input %q", bad)
	}
}

func TestRemember_ResolveExpired(t *testing.T) {
	repo := newFakeRememberRepo()
	svc := NewRemember(repo, time.Hour)
	uid := uuid.New()
	cookie, err := svc.Issue(context.Background(), uid)
	require.NoError(t, err)

	// Force the stored token into the past.
	for _, tk := range repo.byID {
		tk.ExpiresAt = time.Now().Add(-time.Minute)
	}

	_, _, err = svc.Resolve(context.Background(), cookie)
	assert.ErrorIs(t, err, ErrInvalidRememberToken)
	assert.Empty(t, repo.byID, "expired token should be deleted")
}

func TestRemember_WrongValidatorRevokesFamily(t *testing.T) {
	repo := newFakeRememberRepo()
	svc := NewRemember(repo, time.Hour)
	uid := uuid.New()
	cookie, err := svc.Issue(context.Background(), uid)
	require.NoError(t, err)
	// A second token for the same user (another device).
	_, err = svc.Issue(context.Background(), uid)
	require.NoError(t, err)

	tampered := selectorOf(cookie) + ":" + "wrong-validator-value"
	_, _, err = svc.Resolve(context.Background(), tampered)
	assert.ErrorIs(t, err, ErrInvalidRememberToken)
	assert.Empty(t, repo.byID, "theft detection should revoke ALL of the user's tokens")
}

func TestRemember_Revoke(t *testing.T) {
	repo := newFakeRememberRepo()
	svc := NewRemember(repo, time.Hour)
	cookie, err := svc.Issue(context.Background(), uuid.New())
	require.NoError(t, err)

	require.NoError(t, svc.Revoke(context.Background(), cookie))
	_, _, err = svc.Resolve(context.Background(), cookie)
	assert.ErrorIs(t, err, ErrInvalidRememberToken)
}

func TestRemember_RevokeAllForUser(t *testing.T) {
	repo := newFakeRememberRepo()
	svc := NewRemember(repo, time.Hour)
	uid := uuid.New()
	_, _ = svc.Issue(context.Background(), uid)
	_, _ = svc.Issue(context.Background(), uid)
	_, _ = svc.Issue(context.Background(), uuid.New()) // another user

	require.NoError(t, svc.RevokeAllForUser(context.Background(), uid))
	assert.Len(t, repo.byID, 1, "only the other user's token remains")
}

func TestRemember_DefaultLifetime(t *testing.T) {
	svc := NewRemember(newFakeRememberRepo(), 0)
	assert.Equal(t, DefaultRememberLifetime, svc.TTL())
}

func selectorOf(cookie string) string {
	return strings.SplitN(cookie, ":", 2)[0]
}
