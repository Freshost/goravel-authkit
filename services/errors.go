// Package services holds the goravel-authkit business logic: credential
// verification, password changes with other-session invalidation, user
// management, and audit writes. Services never touch the HTTP session — that is
// the controller's concern; they only verify credentials and mutate tables.
//
// Passwords are hashed via the Goravel Hash facade (configure bcrypt cost 12 in
// config/hashing.go). No password or hash is ever logged.
package services

import "errors"

// Sentinel errors. Controllers map these to HTTP status codes via errors.Is.
var (
	// ErrInvalidCredentials is returned for both unknown-email and wrong-password
	// so the response never reveals which.
	ErrInvalidCredentials = errors.New("invalid credentials")
	// ErrValidation is a generic input-validation failure; wrap it with a
	// human-readable message via errors.Join for detail.
	ErrValidation = errors.New("validation error")
	// ErrWrongPassword is returned when the supplied current password is wrong.
	ErrWrongPassword = errors.New("wrong password")
	// ErrNotFound is returned when a requested user does not exist.
	ErrNotFound = errors.New("not found")
	// ErrUnauthorized is returned when the authenticated user no longer exists.
	ErrUnauthorized = errors.New("unauthorized")
	// ErrAlreadyExists is returned when an email collides with an existing user.
	ErrAlreadyExists = errors.New("already exists")
	// ErrLastAdmin is returned when deleting would remove the last admin user.
	ErrLastAdmin = errors.New("cannot remove the last admin")
	// ErrInternal wraps an unexpected lower-layer failure.
	ErrInternal = errors.New("internal error")
)

// DefaultMinPasswordLength is the fallback minimum new-password length when the
// app does not override authkit.min_password_length.
const DefaultMinPasswordLength = 8
