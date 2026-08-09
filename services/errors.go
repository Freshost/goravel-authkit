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
	// ErrForbidden is returned when an authenticated actor is not permitted to
	// perform an action (e.g. an impersonation the authorization gate denies).
	ErrForbidden = errors.New("forbidden")
	// ErrAlreadyExists is returned when an email collides with an existing user.
	ErrAlreadyExists = errors.New("already exists")
	// ErrLastAdmin is returned when an operation (delete, disable, or demote)
	// would leave no active user holding a management/admin role.
	ErrLastAdmin = errors.New("cannot remove the last admin")
	// ErrInternal wraps an unexpected lower-layer failure.
	ErrInternal = errors.New("internal error")
	// ErrTwoFactorNotEnrolled is returned when a 2FA operation needs an active
	// (or pending) enrollment the user does not have.
	ErrTwoFactorNotEnrolled = errors.New("two-factor not enrolled")
	// ErrTwoFactorAlreadyEnabled is returned when enrolling a user who already
	// has 2FA confirmed.
	ErrTwoFactorAlreadyEnabled = errors.New("two-factor already enabled")
	// ErrInvalidCode is returned when a TOTP (or recovery) code does not verify.
	ErrInvalidCode = errors.New("invalid code")
	// ErrInvalidRememberToken is returned when a "remember me" cookie is malformed,
	// unknown, expired, or fails validation.
	ErrInvalidRememberToken = errors.New("invalid remember token")
)

// DefaultMinPasswordLength is the fallback minimum new-password length when the
// app does not override authkit.min_password_length.
const DefaultMinPasswordLength = 8

// MaxPasswordBytes caps accepted passwords at bcrypt's hard limit: bcrypt only
// consumes the first 72 bytes, so anything longer is silently truncated (two
// distinct long passwords sharing a 72-byte prefix would compare equal).
// Rejecting oversize input up front makes that truncation impossible.
const MaxPasswordBytes = 72
