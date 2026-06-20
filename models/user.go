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
	ID                uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	Name              *string    `gorm:"type:text" json:"name,omitempty"`
	Email             string     `gorm:"uniqueIndex;not null" json:"email"`
	EmailVerified     *time.Time `gorm:"type:timestamptz" json:"emailVerified,omitempty"`
	Image             *string    `gorm:"type:text" json:"image,omitempty"`
	PasswordHash      *string    `gorm:"type:text" json:"-"`
	PasswordChangedAt time.Time  `gorm:"type:timestamptz;not null;autoCreateTime" json:"passwordChangedAt"`
	Role              string     `gorm:"type:text;not null;default:'admin'" json:"role"`
	CreatedAt         time.Time  `json:"createdAt"`
	UpdatedAt         time.Time  `json:"updatedAt"`
}

func (User) TableName() string {
	return "users"
}
