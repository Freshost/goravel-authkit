package services

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/freshost/goravel-authkit/models"
	"github.com/freshost/goravel-authkit/repositories"
)

// DefaultSessionActiveWindow bounds how recently a session must have been active
// to count as "current" — mirrors the default session lifetime.
const DefaultSessionActiveWindow = 2 * time.Hour

// SessionView is the service-level projection of a tracked session, with the
// current-session marker resolved (the secret session id is never exposed).
type SessionView struct {
	ID           uuid.UUID
	IP           string
	UserAgent    string
	CreatedAt    time.Time
	LastActiveAt time.Time
	IsCurrent    bool
}

// Sessions manages the active-session list and termination. It tracks one row
// per login; deleting a row terminates that session (its next request is
// rejected by the TrackSession middleware).
type Sessions struct {
	repo         repositories.SessionRepository
	activeWindow time.Duration
}

// NewSessions builds the sessions service. activeWindow <= 0 falls back to
// DefaultSessionActiveWindow; pass the configured session lifetime so the list
// hides sessions whose store entry has already expired.
func NewSessions(repo repositories.SessionRepository, activeWindow time.Duration) *Sessions {
	if activeWindow <= 0 {
		activeWindow = DefaultSessionActiveWindow
	}
	return &Sessions{repo: repo, activeWindow: activeWindow}
}

// Track records the row for a freshly established session (login / remember
// login). It replaces any existing row for the same session id.
func (s *Sessions) Track(ctx context.Context, sessionID string, userID uuid.UUID, ip, userAgent string) error {
	if sessionID == "" {
		return nil
	}
	_ = s.repo.DeleteBySessionID(ctx, sessionID)
	now := time.Now().UTC()
	if err := s.repo.Create(ctx, &models.AuthSession{
		ID:           uuid.New(),
		SessionID:    sessionID,
		UserID:       userID,
		IP:           ip,
		UserAgent:    userAgent,
		LastActiveAt: now,
	}); err != nil {
		return errors.Join(ErrInternal, err)
	}
	return nil
}

// Touch refreshes a session's last-active time and reports whether it still
// exists (false means the row was deleted → the session was terminated).
func (s *Sessions) Touch(ctx context.Context, sessionID string) (bool, error) {
	if sessionID == "" {
		return true, nil
	}
	rows, err := s.repo.TouchLastActive(ctx, sessionID, time.Now().UTC())
	if err != nil {
		return false, errors.Join(ErrInternal, err)
	}
	return rows > 0, nil
}

// List returns the user's active sessions (most recent first), marking the one
// that matches currentSessionID.
func (s *Sessions) List(ctx context.Context, userID uuid.UUID, currentSessionID string) ([]SessionView, error) {
	rows, err := s.repo.ListByUser(ctx, userID, time.Now().Add(-s.activeWindow))
	if err != nil {
		return nil, errors.Join(ErrInternal, err)
	}
	views := make([]SessionView, 0, len(rows))
	for i := range rows {
		r := rows[i]
		views = append(views, SessionView{
			ID:           r.ID,
			IP:           r.IP,
			UserAgent:    r.UserAgent,
			CreatedAt:    r.CreatedAt,
			LastActiveAt: r.LastActiveAt,
			IsCurrent:    r.SessionID == currentSessionID,
		})
	}
	return views, nil
}

// Terminate deletes one of the user's sessions by its public id. It refuses to
// terminate the current session (use logout) and returns ErrNotFound when the id
// is unknown or belongs to another user.
func (s *Sessions) Terminate(ctx context.Context, userID, publicID uuid.UUID, currentSessionID string) error {
	row, err := s.repo.FindByID(ctx, publicID)
	if err != nil {
		return errors.Join(ErrInternal, err)
	}
	if row == nil || row.UserID != userID {
		return ErrNotFound
	}
	if row.SessionID == currentSessionID {
		return errors.Join(ErrValidation, errors.New("cannot terminate the current session"))
	}
	if err := s.repo.DeleteByID(ctx, publicID); err != nil {
		return errors.Join(ErrInternal, err)
	}
	return nil
}

// TerminateOthers deletes every session for the user except the current one.
func (s *Sessions) TerminateOthers(ctx context.Context, userID uuid.UUID, currentSessionID string) error {
	if err := s.repo.DeleteOthersForUser(ctx, userID, currentSessionID); err != nil {
		return errors.Join(ErrInternal, err)
	}
	return nil
}

// Forget removes the row for a session id (used on logout).
func (s *Sessions) Forget(ctx context.Context, sessionID string) error {
	if sessionID == "" {
		return nil
	}
	if err := s.repo.DeleteBySessionID(ctx, sessionID); err != nil {
		return errors.Join(ErrInternal, err)
	}
	return nil
}

// ForgetAllForUser removes every session row for a user (e.g. password change).
func (s *Sessions) ForgetAllForUser(ctx context.Context, userID uuid.UUID) error {
	if err := s.repo.DeleteByUser(ctx, userID); err != nil {
		return errors.Join(ErrInternal, err)
	}
	return nil
}

// PruneStale deletes session rows whose store entry has certainly expired.
func (s *Sessions) PruneStale(ctx context.Context) error {
	if err := s.repo.DeleteStale(ctx, time.Now().Add(-s.activeWindow)); err != nil {
		return errors.Join(ErrInternal, err)
	}
	return nil
}
