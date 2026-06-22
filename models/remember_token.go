package models

import (
	"time"

	"github.com/google/uuid"
)

// RememberToken is a persistent "remember me" login token. It implements the
// selector-validator pattern (OWASP persistent-login best practice): the cookie
// carries "selector:validator", the DB stores the selector in clear (for an
// indexed lookup) and only a hash of the validator. The validator is rotated on
// every use, which both limits the theft window and enables theft detection
// (a stale validator presented for a known selector revokes the whole family).
type RememberToken struct {
	ID            uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	UserID        uuid.UUID `gorm:"type:uuid;not null;index" json:"userId"`
	Selector      string    `gorm:"type:varchar(64);not null;uniqueIndex" json:"selector"`
	ValidatorHash string    `gorm:"type:varchar(64);not null" json:"-"`
	// PreviousValidatorHash is the validator superseded by the most recent
	// rotation. It is accepted for a short grace window (RotatedAt + grace) so
	// concurrent requests carrying the just-rotated-away validator are not
	// mistaken for theft. Empty before the first rotation.
	PreviousValidatorHash string     `gorm:"type:varchar(64);not null;default:''" json:"-"`
	RotatedAt             *time.Time `gorm:"type:timestamptz" json:"-"`
	ExpiresAt             time.Time  `gorm:"type:timestamptz;not null" json:"expiresAt"`
	CreatedAt             time.Time  `json:"createdAt"`
}

func (RememberToken) TableName() string {
	return "auth_remember_tokens"
}
