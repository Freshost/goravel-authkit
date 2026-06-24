package models

import (
	"time"

	"github.com/google/uuid"
)

// AuthSession tracks one active login so a user can see and terminate their
// sessions (Goravel's session store is not indexed by user). SessionID holds
// authkit's stable per-guard tracking token (NOT the Goravel session id, which
// rotates on every login) and is never serialized; the public ID is used to
// address a session for termination. A request whose session has no row is
// treated as terminated.
type AuthSession struct {
	ID           uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	SessionID    string    `gorm:"type:varchar(255);not null;uniqueIndex" json:"-"`
	UserID       uuid.UUID `gorm:"type:uuid;not null;index" json:"userId"`
	IP           string    `gorm:"type:varchar(64)" json:"ip,omitempty"`
	UserAgent    string    `gorm:"type:text" json:"userAgent,omitempty"`
	CreatedAt    time.Time `json:"createdAt"`
	LastActiveAt time.Time `gorm:"type:timestamptz;not null" json:"lastActiveAt"`
}

func (AuthSession) TableName() string {
	return "auth_sessions"
}
