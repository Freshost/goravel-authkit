package authkit

import (
	"context"

	"github.com/google/uuid"
	"github.com/goravel/framework/contracts/foundation"

	"github.com/freshost/goravel-authkit/contracts"
	"github.com/freshost/goravel-authkit/models"
	"github.com/freshost/goravel-authkit/repositories"
	"github.com/freshost/goravel-authkit/services"
)

// Authkit is the concrete implementation behind facades.Authkit(). It wraps the
// auth + user-management services so app code can drive them programmatically.
type Authkit struct {
	auth  *services.Auth
	users *services.Users
}

var _ contracts.Authkit = (*Authkit)(nil)

// NewAuthkit builds the service from the application (read lazily at resolve
// time, so config is available).
func NewAuthkit(app foundation.Application) *Authkit {
	minPwLen := services.DefaultMinPasswordLength
	if cfg := app.MakeConfig(); cfg != nil {
		if v := cfg.GetInt("authkit.min_password_length", minPwLen); v > 0 {
			minPwLen = v
		}
	}
	repo := repositories.NewUsers()
	hasher := services.NewFacadeHasher()
	return &Authkit{
		auth:  services.NewAuth(repo, hasher, minPwLen),
		users: services.NewUsers(repo, hasher, minPwLen),
	}
}

func (a *Authkit) Authenticate(ctx context.Context, email, password string) (*models.User, error) {
	return a.auth.Authenticate(ctx, email, password)
}

func (a *Authkit) CreateUser(ctx context.Context, email, name, password, role string) (*models.User, error) {
	return a.users.Create(ctx, email, name, password, role)
}

func (a *Authkit) GetUser(ctx context.Context, id uuid.UUID) (*models.User, error) {
	return a.users.GetByID(ctx, id)
}

func (a *Authkit) ListUsers(ctx context.Context) ([]models.User, error) {
	return a.users.List(ctx)
}

func (a *Authkit) SetPassword(ctx context.Context, id uuid.UUID, newPassword string) (*models.User, error) {
	return a.users.SetPassword(ctx, id, newPassword)
}

func (a *Authkit) ChangePassword(ctx context.Context, id uuid.UUID, currentPassword, newPassword string) error {
	_, err := a.auth.ChangePassword(ctx, id, currentPassword, newPassword)
	return err
}

func (a *Authkit) DeleteUser(ctx context.Context, id uuid.UUID) error {
	return a.users.Delete(ctx, id)
}
