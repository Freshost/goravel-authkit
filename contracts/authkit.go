// Package contracts defines the public interface exposed by the goravel-authkit
// facade. Consuming apps call it via facades.Authkit() to drive user/auth
// operations programmatically (seeders, installers, custom CLI, domain code)
// without going through the HTTP endpoints.
package contracts

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/freshost/goravel-authkit/models"
)

type IssueAPITokenInput struct {
	UserID        uuid.UUID
	Name          string
	ExpiresAt     time.Time
	Scopes        []string
	Password      string
	TwoFactorCode string
}

type IssuedAPIToken struct {
	Token     *models.APIToken
	Plaintext string
}

// Authkit is the programmatic API of the goravel-authkit package.
type Authkit interface {
	// Authenticate verifies credentials and returns the matching user. Returns a
	// generic invalid-credentials error for both unknown-email and wrong-password.
	Authenticate(ctx context.Context, email, password string) (*models.User, error)
	// CreateUser creates a user (idempotent callers check for an already-exists
	// error). role defaults to "admin" when empty.
	CreateUser(ctx context.Context, email, name, password, role string) (*models.User, error)
	// GetUser returns a user by id, or a not-found error.
	GetUser(ctx context.Context, id uuid.UUID) (*models.User, error)
	// ListUsers returns all users.
	ListUsers(ctx context.Context) ([]models.User, error)
	// SetPassword resets a user's password (admin action); invalidates that
	// user's existing sessions.
	SetPassword(ctx context.Context, id uuid.UUID, newPassword string) (*models.User, error)
	// ChangePassword verifies the current password before setting a new one;
	// invalidates the user's OTHER sessions.
	ChangePassword(ctx context.Context, id uuid.UUID, currentPassword, newPassword string) error
	// DeleteUser removes a user, refusing to remove the last one.
	DeleteUser(ctx context.Context, id uuid.UUID) error

	// EnableTwoFactor starts TOTP enrollment, returning the secret + otpauth URL
	// (the user confirms with a code to activate).
	EnableTwoFactor(ctx context.Context, id uuid.UUID) (secret, otpauthURL string, err error)
	// ConfirmTwoFactor verifies a code against the pending secret, activates 2FA,
	// and returns one-time recovery codes.
	ConfirmTwoFactor(ctx context.Context, id uuid.UUID, code string) (recoveryCodes []string, err error)
	// VerifyTwoFactor checks a TOTP code for a 2FA-enabled user.
	VerifyTwoFactor(ctx context.Context, id uuid.UUID, code string) (bool, error)
	// DisableTwoFactor clears the user's two-factor state.
	DisableTwoFactor(ctx context.Context, id uuid.UUID) error

	IssueAPIToken(ctx context.Context, input IssueAPITokenInput) (*IssuedAPIToken, error)
	ListAPITokens(ctx context.Context, userID uuid.UUID) ([]models.APIToken, error)
	RevokeAPIToken(ctx context.Context, userID, tokenID uuid.UUID) error
	RevokeAllAPITokens(ctx context.Context, userID uuid.UUID) error
}
