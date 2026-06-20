// Package contracts defines the public interface exposed by the goravel-authkit
// facade. Consuming apps call it via facades.Authkit() to drive user/auth
// operations programmatically (seeders, installers, custom CLI, domain code)
// without going through the HTTP endpoints.
package contracts

import (
	"context"

	"github.com/google/uuid"

	"github.com/freshost/goravel-authkit/models"
)

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
}
