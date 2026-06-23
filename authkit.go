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
// auth + user-management + two-factor services so app code can drive them
// programmatically.
type Authkit struct {
	auth      *services.Auth
	users     *services.Users
	twoFactor *services.TwoFactor
}

var _ contracts.Authkit = (*Authkit)(nil)

// NewAuthkit builds the service from the application (read lazily at resolve
// time, so config is available).
func NewAuthkit(app foundation.Application) *Authkit {
	minPwLen := services.DefaultMinPasswordLength
	issuer := ""
	recoveryCount := services.DefaultRecoveryCodeCount
	var roles, managementRoles []string
	if cfg := app.MakeConfig(); cfg != nil {
		if v := cfg.GetInt("authkit.min_password_length", minPwLen); v > 0 {
			minPwLen = v
		}
		issuer = cfg.GetString("authkit.two_factor.issuer")
		if v := cfg.GetInt("authkit.two_factor.recovery_codes", recoveryCount); v > 0 {
			recoveryCount = v
		}
		roles = toStringSlice(cfg.Get("authkit.roles"))
		managementRoles = toStringSlice(cfg.Get("authkit.user_management_roles"))
	}
	// Fail-closed: management roles default to the admin role so the last-admin
	// guards work even when the app leaves user_management_roles unset.
	if len(managementRoles) == 0 {
		managementRoles = []string{services.AdminRole}
	}
	repo := repositories.NewUsers()
	hasher := services.NewFacadeHasher()
	return &Authkit{
		auth:      services.NewAuth(repo, hasher, minPwLen),
		users:     services.NewUsers(repo, hasher, minPwLen, roles, managementRoles),
		twoFactor: services.NewTwoFactor(repo, services.NewFacadeCrypter(), issuer, recoveryCount),
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

func (a *Authkit) EnableTwoFactor(ctx context.Context, id uuid.UUID) (secret, otpauthURL string, err error) {
	enr, err := a.twoFactor.Enable(ctx, id)
	if err != nil {
		return "", "", err
	}
	return enr.Secret, enr.OtpauthURL, nil
}

func (a *Authkit) ConfirmTwoFactor(ctx context.Context, id uuid.UUID, code string) ([]string, error) {
	return a.twoFactor.Confirm(ctx, id, code)
}

func (a *Authkit) VerifyTwoFactor(ctx context.Context, id uuid.UUID, code string) (bool, error) {
	user, err := a.users.GetByID(ctx, id)
	if err != nil {
		return false, err
	}
	return a.twoFactor.Verify(user, code)
}

func (a *Authkit) DisableTwoFactor(ctx context.Context, id uuid.UUID) error {
	return a.twoFactor.Disable(ctx, id)
}

// toStringSlice coerces a config value (set as []string or []any in the Go
// config file) into []string, dropping non-string entries.
func toStringSlice(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}
