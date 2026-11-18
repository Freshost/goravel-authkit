package repositories

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	ormcontract "github.com/goravel/framework/contracts/database/orm"
	"github.com/goravel/framework/facades"
	"gorm.io/gorm"

	"github.com/freshost/goravel-authkit/models"
)

// DefaultSessionsTable is the table the bare NewSessions() constructor binds to.
const DefaultSessionsTable = "auth_sessions"

// SessionRepository persists the active-session tracking rows. As elsewhere,
// FindByID returns (nil, nil) — not an error — when no row matches.
type SessionRepository interface {
	Create(ctx context.Context, s *models.AuthSession) error
	FindByID(ctx context.Context, id uuid.UUID) (*models.AuthSession, error)
	// TouchLastActive bumps last_active_at for a session; returns rows affected
	// (0 means the row is gone → the session was terminated).
	TouchLastActive(ctx context.Context, sessionID string, t time.Time) (int64, error)
	ListByUser(ctx context.Context, userID uuid.UUID, activeSince time.Time) ([]models.AuthSession, error)
	DeleteByID(ctx context.Context, id uuid.UUID) error
	DeleteBySessionID(ctx context.Context, sessionID string) error
	DeleteOthersForUser(ctx context.Context, userID uuid.UUID, exceptSessionID string) error
	DeleteByUser(ctx context.Context, userID uuid.UUID) error
	DeleteStale(ctx context.Context, before time.Time) error
}

// Sessions is the ORM-backed SessionRepository, bound to a concrete table.
type Sessions struct{ table, rememberTable string }

// NewSessions returns an ORM-backed sessions repository over the default table.
func NewSessions() *Sessions { return NewSessionsWithTable(DefaultSessionsTable) }

// NewSessionsWithTable returns an ORM-backed sessions repository over the named table.
func NewSessionsWithTable(table string, rememberTables ...string) *Sessions {
	if table == "" {
		table = DefaultSessionsTable
	}
	remember := DefaultRememberTokensTable
	if len(rememberTables) > 0 && rememberTables[0] != "" {
		remember = rememberTables[0]
	}
	return &Sessions{table: table, rememberTable: remember}
}

var _ SessionRepository = (*Sessions)(nil)

func (r *Sessions) query(ctx context.Context) ormcontract.Query {
	return facades.Orm().WithContext(ctx).Query().Table(r.table)
}

func (r *Sessions) Create(ctx context.Context, s *models.AuthSession) error {
	return facades.Orm().WithContext(ctx).Transaction(func(tx ormcontract.Query) error {
		if s.RememberSelector != "" {
			var credential models.RememberToken
			if err := tx.Table(r.rememberTable).Where("selector", s.RememberSelector).Where("session_id", s.SessionID).Where("user_id", s.UserID).LockForUpdate().First(&credential); err != nil {
				return err
			}
			if credential.ID == uuid.Nil || !time.Now().Before(credential.ExpiresAt) {
				return gorm.ErrRecordNotFound
			}
		}
		var previous models.AuthSession
		if err := tx.Table(r.table).Where("session_id", s.SessionID).LockForUpdate().First(&previous); err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		if previous.ID != uuid.Nil {
			if previous.UserID != s.UserID {
				return gorm.ErrRecordNotFound
			}
			s.ID, s.CreatedAt = previous.ID, previous.CreatedAt
		}
		return tx.Table(r.table).Save(s)
	})
}

func (r *Sessions) FindByID(ctx context.Context, id uuid.UUID) (*models.AuthSession, error) {
	var s models.AuthSession
	err := r.query(ctx).Where("id", id).First(&s)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if s.ID == uuid.Nil {
		return nil, nil
	}
	return &s, nil
}

func (r *Sessions) TouchLastActive(ctx context.Context, sessionID string, t time.Time) (int64, error) {
	res, err := r.query(ctx).
		Where("session_id", sessionID).Update("last_active_at", t)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected, nil
}

func (r *Sessions) ListByUser(ctx context.Context, userID uuid.UUID, activeSince time.Time) ([]models.AuthSession, error) {
	var sessions []models.AuthSession
	if err := r.query(ctx).
		Where("user_id", userID).Where("last_active_at >= ?", activeSince).
		Order("last_active_at desc").Find(&sessions); err != nil {
		return nil, err
	}
	return sessions, nil
}

// Delete the persistent credential first so a concurrent restore cannot replace a revoked session.
func (r *Sessions) delete(ctx context.Context, condition string, args ...any) error {
	return facades.Orm().WithContext(ctx).Transaction(func(tx ormcontract.Query) error {
		var credentials []models.RememberToken
		if err := tx.Table(r.rememberTable).Where(condition, args...).OrderBy("id").LockForUpdate().Find(&credentials); err != nil {
			return err
		}
		if _, err := tx.Table(r.rememberTable).Where(condition, args...).Delete(&models.RememberToken{}); err != nil {
			return err
		}
		_, err := tx.Table(r.table).Where(condition, args...).Delete(&models.AuthSession{})
		return err
	})
}
func (r *Sessions) DeleteByID(ctx context.Context, id uuid.UUID) error {
	session, err := r.FindByID(ctx, id)
	if err != nil || session == nil {
		return err
	}
	return r.DeleteBySessionID(ctx, session.SessionID)
}
func (r *Sessions) DeleteBySessionID(ctx context.Context, sessionID string) error {
	return r.delete(ctx, "session_id = ?", sessionID)
}
func (r *Sessions) DeleteOthersForUser(ctx context.Context, userID uuid.UUID, exceptSessionID string) error {
	return r.delete(ctx, "user_id = ? AND session_id != ?", userID, exceptSessionID)
}
func (r *Sessions) DeleteByUser(ctx context.Context, userID uuid.UUID) error {
	return r.delete(ctx, "user_id = ?", userID)
}

func (r *Sessions) DeleteStale(ctx context.Context, before time.Time) error {
	_, err := r.query(ctx).Where("last_active_at < ?", before).Delete(&models.AuthSession{})
	return err
}
