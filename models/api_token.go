package models

import (
	"time"

	"github.com/google/uuid"
)

// APIToken is one revocable personal access token. The plaintext validator is
// returned only at issuance; only its SHA-256 hash is persisted.
type APIToken struct {
	ID            uuid.UUID   `gorm:"type:uuid;primaryKey" json:"id"`
	UserID        uuid.UUID   `gorm:"type:uuid;not null;index" json:"userId"`
	Name          string      `gorm:"type:varchar(100);not null" json:"name"`
	Selector      string      `gorm:"type:varchar(32);not null;uniqueIndex" json:"-"`
	ValidatorHash string      `gorm:"type:varchar(64);not null" json:"-"`
	Scopes        StringSlice `gorm:"type:jsonb;not null" json:"scopes"`
	ExpiresAt     time.Time   `gorm:"type:timestamptz;not null;index" json:"expiresAt"`
	LastUsedAt    *time.Time  `gorm:"type:timestamptz" json:"lastUsedAt,omitempty"`
	RevokedAt     *time.Time  `gorm:"type:timestamptz;index" json:"-"`
	CreatedAt     time.Time   `json:"createdAt"`
}

func (APIToken) TableName() string { return "api_tokens" }

func (t *APIToken) Active(now time.Time) bool {
	return t != nil && t.RevokedAt == nil && now.Before(t.ExpiresAt)
}
