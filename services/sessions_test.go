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

// fakeSessionRepo is an in-memory SessionRepository for service unit tests.
type fakeSessionRepo struct {
	byID map[uuid.UUID]*models.AuthSession
}

func newFakeSessionRepo() *fakeSessionRepo {
	return &fakeSessionRepo{byID: map[uuid.UUID]*models.AuthSession{}}
}

func (f *fakeSessionRepo) Create(_ context.Context, s *models.AuthSession) error {
	cp := *s
	f.byID[s.ID] = &cp
	return nil
}

func (f *fakeSessionRepo) FindByID(_ context.Context, id uuid.UUID) (*models.AuthSession, error) {
	if s, ok := f.byID[id]; ok {
		cp := *s
		return &cp, nil
	}
	return nil, nil
}

func (f *fakeSessionRepo) TouchLastActive(_ context.Context, sessionID string, t time.Time) (int64, error) {
	for _, s := range f.byID {
		if s.SessionID == sessionID {
			s.LastActiveAt = t
			return 1, nil
		}
	}
	return 0, nil
}

func (f *fakeSessionRepo) ListByUser(_ context.Context, userID uuid.UUID, activeSince time.Time) ([]models.AuthSession, error) {
	var out []models.AuthSession
	for _, s := range f.byID {
		if s.UserID == userID && !s.LastActiveAt.Before(activeSince) {
			out = append(out, *s)
		}
	}
	return out, nil
}

func (f *fakeSessionRepo) DeleteByID(_ context.Context, id uuid.UUID) error {
	delete(f.byID, id)
	return nil
}

func (f *fakeSessionRepo) DeleteBySessionID(_ context.Context, sessionID string) error {
	for id, s := range f.byID {
		if s.SessionID == sessionID {
			delete(f.byID, id)
		}
	}
	return nil
}

func (f *fakeSessionRepo) DeleteOthersForUser(_ context.Context, userID uuid.UUID, exceptSessionID string) error {
	for id, s := range f.byID {
		if s.UserID == userID && s.SessionID != exceptSessionID {
			delete(f.byID, id)
		}
	}
	return nil
}

func (f *fakeSessionRepo) DeleteByUser(_ context.Context, userID uuid.UUID) error {
	for id, s := range f.byID {
		if s.UserID == userID {
			delete(f.byID, id)
		}
	}
	return nil
}

func (f *fakeSessionRepo) DeleteStale(_ context.Context, before time.Time) error {
	for id, s := range f.byID {
		if s.LastActiveAt.Before(before) {
			delete(f.byID, id)
		}
	}
	return nil
}

func TestSessions_TrackListAndCurrent(t *testing.T) {
	repo := newFakeSessionRepo()
	svc := NewSessions(repo, time.Hour)
	uid := uuid.New()

	require.NoError(t, svc.Track(context.Background(), "sess-A", uid, "1.1.1.1", "Firefox"))
	require.NoError(t, svc.Track(context.Background(), "sess-B", uid, "2.2.2.2", "Chrome"))

	views, err := svc.List(context.Background(), uid, "sess-A")
	require.NoError(t, err)
	assert.Len(t, views, 2)
	var current int
	for _, v := range views {
		if v.IsCurrent {
			current++
		}
	}
	assert.Equal(t, 1, current, "exactly one session is marked current")
}

func TestSessions_TouchReportsTermination(t *testing.T) {
	repo := newFakeSessionRepo()
	svc := NewSessions(repo, time.Hour)
	require.NoError(t, svc.Track(context.Background(), "sess-A", uuid.New(), "", ""))

	alive, err := svc.Touch(context.Background(), "sess-A")
	require.NoError(t, err)
	assert.True(t, alive)

	require.NoError(t, svc.Forget(context.Background(), "sess-A"))
	alive, err = svc.Touch(context.Background(), "sess-A")
	require.NoError(t, err)
	assert.False(t, alive, "a forgotten session is reported terminated")
}

func TestSessions_TerminateByID(t *testing.T) {
	repo := newFakeSessionRepo()
	svc := NewSessions(repo, time.Hour)
	uid := uuid.New()
	require.NoError(t, svc.Track(context.Background(), "sess-A", uid, "", ""))
	require.NoError(t, svc.Track(context.Background(), "sess-B", uid, "", ""))

	views, _ := svc.List(context.Background(), uid, "sess-A")
	var bID uuid.UUID
	for _, v := range views {
		if !v.IsCurrent {
			bID = v.ID
		}
	}

	// Terminating another session succeeds.
	require.NoError(t, svc.Terminate(context.Background(), uid, bID, "sess-A"))
	alive, _ := svc.Touch(context.Background(), "sess-B")
	assert.False(t, alive)
}

func TestSessions_TerminateCurrentRefused(t *testing.T) {
	repo := newFakeSessionRepo()
	svc := NewSessions(repo, time.Hour)
	uid := uuid.New()
	require.NoError(t, svc.Track(context.Background(), "sess-A", uid, "", ""))
	views, _ := svc.List(context.Background(), uid, "sess-A")
	aID := views[0].ID

	err := svc.Terminate(context.Background(), uid, aID, "sess-A")
	assert.ErrorIs(t, err, ErrValidation)
}

func TestSessions_TerminateForeignNotFound(t *testing.T) {
	repo := newFakeSessionRepo()
	svc := NewSessions(repo, time.Hour)
	owner := uuid.New()
	require.NoError(t, svc.Track(context.Background(), "sess-A", owner, "", ""))
	views, _ := svc.List(context.Background(), owner, "")
	aID := views[0].ID

	// A different user cannot terminate it.
	err := svc.Terminate(context.Background(), uuid.New(), aID, "other")
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestSessions_TerminateOthersKeepsCurrent(t *testing.T) {
	repo := newFakeSessionRepo()
	svc := NewSessions(repo, time.Hour)
	uid := uuid.New()
	require.NoError(t, svc.Track(context.Background(), "sess-A", uid, "", ""))
	require.NoError(t, svc.Track(context.Background(), "sess-B", uid, "", ""))
	require.NoError(t, svc.Track(context.Background(), "sess-C", uid, "", ""))

	require.NoError(t, svc.TerminateOthers(context.Background(), uid, "sess-A"))
	views, _ := svc.List(context.Background(), uid, "sess-A")
	require.Len(t, views, 1)
	assert.True(t, views[0].IsCurrent)
}

func TestSessions_ListHidesStale(t *testing.T) {
	repo := newFakeSessionRepo()
	svc := NewSessions(repo, time.Hour)
	uid := uuid.New()
	require.NoError(t, svc.Track(context.Background(), "fresh", uid, "", ""))
	require.NoError(t, svc.Track(context.Background(), "stale", uid, "", ""))
	// Age the stale one past the active window.
	for _, s := range repo.byID {
		if s.SessionID == "stale" {
			s.LastActiveAt = time.Now().Add(-2 * time.Hour)
		}
	}

	views, err := svc.List(context.Background(), uid, "fresh")
	require.NoError(t, err)
	assert.Len(t, views, 1)
}
