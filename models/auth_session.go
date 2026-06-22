package models

import (
	"time"

	"github.com/google/uuid"
)

// AuthSession tracks one active login so a user can see and terminate their
// sessions (Goravel's session store is not indexed by user). SessionID is the
// secret session identifier and is never serialized; the public ID is used to
// address a session for termination. A request whose session has no row is
// treated as terminated.
type AuthSession struct {
	ID           uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
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
