package repositories

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/goravel/framework/facades"
	"gorm.io/gorm"

	"github.com/freshost/goravel-authkit/models"
)

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

// Sessions is the ORM-backed SessionRepository.
type Sessions struct{}

// NewSessions returns an ORM-backed sessions repository.
func NewSessions() *Sessions {
	return &Sessions{}
}

var _ SessionRepository = (*Sessions)(nil)

func (r *Sessions) Create(ctx context.Context, s *models.AuthSession) error {
	return facades.Orm().WithContext(ctx).Query().Create(s)
}

func (r *Sessions) FindByID(ctx context.Context, id uuid.UUID) (*models.AuthSession, error) {
	var s models.AuthSession
	err := facades.Orm().WithContext(ctx).Query().Where("id", id).First(&s)
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
	res, err := facades.Orm().WithContext(ctx).Query().Model(&models.AuthSession{}).
		Where("session_id", sessionID).Update("last_active_at", t)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected, nil
}

func (r *Sessions) ListByUser(ctx context.Context, userID uuid.UUID, activeSince time.Time) ([]models.AuthSession, error) {
	var sessions []models.AuthSession
	if err := facades.Orm().WithContext(ctx).Query().
		Where("user_id", userID).Where("last_active_at >= ?", activeSince).
		Order("last_active_at desc").Find(&sessions); err != nil {
		return nil, err
	}
	return sessions, nil
}

func (r *Sessions) DeleteByID(ctx context.Context, id uuid.UUID) error {
	_, err := facades.Orm().WithContext(ctx).Query().Where("id", id).Delete(&models.AuthSession{})
	return err
}

func (r *Sessions) DeleteBySessionID(ctx context.Context, sessionID string) error {
	_, err := facades.Orm().WithContext(ctx).Query().Where("session_id", sessionID).Delete(&models.AuthSession{})
	return err
}

func (r *Sessions) DeleteOthersForUser(ctx context.Context, userID uuid.UUID, exceptSessionID string) error {
	_, err := facades.Orm().WithContext(ctx).Query().
		Where("user_id", userID).Where("session_id != ?", exceptSessionID).
		Delete(&models.AuthSession{})
	return err
}

func (r *Sessions) DeleteByUser(ctx context.Context, userID uuid.UUID) error {
	_, err := facades.Orm().WithContext(ctx).Query().Where("user_id", userID).Delete(&models.AuthSession{})
	return err
}

func (r *Sessions) DeleteStale(ctx context.Context, before time.Time) error {
	_, err := facades.Orm().WithContext(ctx).Query().Where("last_active_at < ?", before).Delete(&models.AuthSession{})
	return err
}
