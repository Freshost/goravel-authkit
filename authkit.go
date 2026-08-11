package authkit

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/goravel/framework/contracts/foundation"

	"github.com/freshost/goravel-authkit/contracts"
	"github.com/freshost/goravel-authkit/models"
	"github.com/freshost/goravel-authkit/repositories"
	"github.com/freshost/goravel-authkit/services"
)

// Config describes one programmatic authkit instance: which user table it
// operates on plus the password / two-factor / role policy. Every field is
// optional — the zero value reproduces the single-instance defaults — so a host
// running two user domains builds one instance per domain:
//
//	client := authkit.New(authkit.Config{Guard: "client", UsersTable: "accounts"})
//	admin  := authkit.New(authkit.Config{Guard: "admin", UsersTable: "admin_users"})
type Config struct {
	// Guard is the Goravel guard this instance represents (e.g. "client"). It is
	// recorded for symmetry with routes.Options; the programmatic methods operate
	// directly on UsersTable and do not resolve a guard.
	Guard string
	// UsersTable is the table this instance's users live in (default "" → "users").
	UsersTable string
	// MinPasswordLength is the minimum accepted new-password length (default → DefaultMinPasswordLength).
	MinPasswordLength int
	// TwoFactorIssuer is the issuer shown in the authenticator app.
	TwoFactorIssuer string
	// RecoveryCodeCount is how many recovery codes confirmation generates (default → DefaultRecoveryCodeCount).
	RecoveryCodeCount int
	// Roles, when non-empty, is the set of role values accepted on create/update.
	Roles []string
	// UserManagementRoles gates the management invariants (default → AdminRole).
	UserManagementRoles []string
	// APITokensTable is the per-guard personal access token table.
	APITokensTable                string
	APITokenAllowedScopes         []string
	APITokenMaxLifetime           time.Duration
	APITokenMaxPerUser            int
	KeepAPITokensOnPasswordChange bool
}

// Authkit is the concrete implementation behind facades.Authkit() and the value
// returned by New. It wraps the auth + user-management + two-factor services so
// app code can drive them programmatically against a specific user table.
type Authkit struct {
	auth                            *services.Auth
	users                           *services.Users
	twoFactor                       *services.TwoFactor
	apiTokens                       *services.APITokens
	revokeAPITokensOnPasswordChange bool
}

var _ contracts.Authkit = (*Authkit)(nil)

// New builds a programmatic authkit instance bound to cfg.UsersTable. Zero-valued
// fields fall back to the package defaults, so authkit.New(authkit.Config{})
// behaves exactly like the default single-instance service.
func New(cfg Config) *Authkit {
	minPwLen := cfg.MinPasswordLength
	if minPwLen <= 0 {
		minPwLen = services.DefaultMinPasswordLength
	}
	recoveryCount := cfg.RecoveryCodeCount
	if recoveryCount <= 0 {
		recoveryCount = services.DefaultRecoveryCodeCount
	}
	// Fail-closed: management roles default to the admin role so the last-admin
	// guards work even when the caller leaves UserManagementRoles unset.
	managementRoles := cfg.UserManagementRoles
	if len(managementRoles) == 0 {
		managementRoles = []string{services.AdminRole}
	}
	repo := repositories.NewUsersWithTable(cfg.UsersTable)
	hasher := services.NewFacadeHasher()
	twoFactor := services.NewTwoFactor(repo, services.NewFacadeCrypter(), cfg.TwoFactorIssuer, recoveryCount)
	apiTokens := services.NewAPITokens(repositories.NewAPITokensWithTable(cfg.APITokensTable), repo, hasher, twoFactor, cfg.APITokenAllowedScopes, cfg.APITokenMaxLifetime, cfg.APITokenMaxPerUser)
	return &Authkit{
		auth:                            services.NewAuth(repo, hasher, minPwLen),
		users:                           services.NewUsers(repo, hasher, minPwLen, cfg.Roles, managementRoles, apiTokens, !cfg.KeepAPITokensOnPasswordChange),
		twoFactor:                       twoFactor,
		apiTokens:                       apiTokens,
		revokeAPITokensOnPasswordChange: !cfg.KeepAPITokensOnPasswordChange,
	}
}

// NewAuthkit builds the default instance from the published authkit.* config
// (read lazily at resolve time, so config is available). It is the thin wrapper
// behind facades.Authkit(); multi-table hosts use New directly.
func NewAuthkit(app foundation.Application) *Authkit {
	var cfg Config
	if c := app.MakeConfig(); c != nil {
		cfg = Config{
			Guard:                         c.GetString("authkit.guard"),
			UsersTable:                    c.GetString("authkit.tables.users"),
			MinPasswordLength:             c.GetInt("authkit.min_password_length"),
			TwoFactorIssuer:               c.GetString("authkit.two_factor.issuer"),
			RecoveryCodeCount:             c.GetInt("authkit.two_factor.recovery_codes"),
			Roles:                         toStringSlice(c.Get("authkit.roles")),
			UserManagementRoles:           toStringSlice(c.Get("authkit.user_management_roles")),
			APITokensTable:                c.GetString("authkit.tables.api_tokens"),
			APITokenAllowedScopes:         toStringSlice(c.Get("authkit.api_tokens.allowed_scopes")),
			APITokenMaxLifetime:           time.Duration(c.GetInt("authkit.api_tokens.max_lifetime_days")) * 24 * time.Hour,
			APITokenMaxPerUser:            c.GetInt("authkit.api_tokens.max_per_user"),
			KeepAPITokensOnPasswordChange: !c.GetBool("authkit.api_tokens.revoke_on_password_change", true),
		}
	}
	return New(cfg)
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
	if err == nil && a.revokeAPITokensOnPasswordChange {
		err = a.apiTokens.RevokeAll(ctx, id)
	}
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

func (a *Authkit) IssueAPIToken(ctx context.Context, input contracts.IssueAPITokenInput) (*contracts.IssuedAPIToken, error) {
	issued, err := a.apiTokens.Issue(ctx, services.IssueAPITokenCommand{
		UserID: input.UserID, Name: input.Name, ExpiresAt: input.ExpiresAt, Scopes: input.Scopes,
		Password: input.Password, TwoFactorCode: input.TwoFactorCode,
	})
	if err != nil {
		return nil, err
	}
	return &contracts.IssuedAPIToken{Token: issued.Token, Plaintext: issued.Plaintext}, nil
}

func (a *Authkit) ListAPITokens(ctx context.Context, userID uuid.UUID) ([]models.APIToken, error) {
	return a.apiTokens.List(ctx, userID)
}

func (a *Authkit) RevokeAPIToken(ctx context.Context, userID, tokenID uuid.UUID) error {
	return a.apiTokens.Revoke(ctx, userID, tokenID)
}

func (a *Authkit) RevokeAllAPITokens(ctx context.Context, userID uuid.UUID) error {
	return a.apiTokens.RevokeAll(ctx, userID)
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
