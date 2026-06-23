// Package models holds the canonical GORM entities owned by the goravel-authkit
// package: the single User table backing authentication and the AuditLog table.
//
// The User model is intentionally Auth.js-shaped (nullable Name/Image/
// EmailVerified, nullable PasswordHash) so a project can later add OAuth/
// passwordless flows without a schema change. PasswordChangedAt is stamped on
// every password change and compared on each request to invalidate other
// sessions.
package models

import (
	"time"

	"github.com/google/uuid"
)

// User is the account record owned by goravel-authkit. Apps that adopt the package
// share this exact shape (table "users"); the package's repositories and
// services operate on it directly. PasswordHash is never serialized to JSON.
type User struct {
	ID                uuid.UUID  `gorm:"type:uuid;primaryKey" json:"id"`
	Name              *string    `gorm:"type:text" json:"name,omitempty"`
	Email             string     `gorm:"uniqueIndex;not null" json:"email"`
	EmailVerified     *time.Time `gorm:"type:timestamptz" json:"emailVerified,omitempty"`
	Image             *string    `gorm:"type:text" json:"image,omitempty"`
	PasswordHash      *string    `gorm:"type:text" json:"-"`
	PasswordChangedAt time.Time  `gorm:"type:timestamptz;not null;autoCreateTime" json:"passwordChangedAt"`
	// Role has no DB-level default: the service always sets it explicitly so a
	// created row can never silently become "admin" (privilege escalation).
	Role string `gorm:"type:text;not null" json:"role"`
	// DisabledAt, when set, locks the account: login is refused and any live
	// session / remember cookie is rejected on its next request. nil = active.
	DisabledAt *time.Time `gorm:"type:timestamptz" json:"disabledAt,omitempty"`

	// Two-factor (TOTP). Secret + recovery codes are stored encrypted (Crypt
	// facade) and never serialized. TwoFactorConfirmedAt is set once the user
	// confirms enrollment; nil means 2FA is not active.
	TwoFactorSecret        *string    `gorm:"type:text" json:"-"`
	TwoFactorRecoveryCodes *string    `gorm:"type:text" json:"-"`
	TwoFactorConfirmedAt   *time.Time `gorm:"type:timestamptz" json:"-"`
	// Start time of the last accepted TOTP step; rejects replay within a code's
	// validity window (single-use TOTP).
	TwoFactorLastUsedAt *time.Time `gorm:"type:timestamptz" json:"-"`

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func (User) TableName() string {
	return "users"
}

// TwoFactorEnabled reports whether the user has confirmed TOTP two-factor auth.
func (u *User) TwoFactorEnabled() bool {
	return u.TwoFactorConfirmedAt != nil && u.TwoFactorSecret != nil && *u.TwoFactorSecret != ""
}

// IsDisabled reports whether the account is locked (DisabledAt set).
func (u *User) IsDisabled() bool {
	return u.DisabledAt != nil
}
