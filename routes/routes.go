// Package routes registers the goravel-authkit HTTP endpoints onto a consuming
// app's router. The app calls Register from its own routes file so the package
// controllers land in the app's import graph (required for `swag` to scan their
// annotations into the OpenAPI contract).
package routes

import (
	"time"

	contractshttp "github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/contracts/route"
	"github.com/goravel/framework/facades"
	sessionmiddleware "github.com/goravel/framework/session/middleware"

	authcontracts "github.com/freshost/goravel-authkit/contracts"
	"github.com/freshost/goravel-authkit/http/controllers"
	"github.com/freshost/goravel-authkit/http/middleware"
	"github.com/freshost/goravel-authkit/http/responses"
	"github.com/freshost/goravel-authkit/repositories"
	"github.com/freshost/goravel-authkit/services"
)

// Options configures route registration and the behaviour of the wired
// controllers. Use DefaultOptions or OptionsFromConfig as a base.
type Options struct {
	// Prefix is prepended to every route (e.g. "/api/v1").
	Prefix string
	// Guard is the Goravel auth guard name backing the session (e.g. "admin").
	Guard string
	// MinPasswordLength is the minimum accepted new-password length.
	MinPasswordLength int
	// RateLimitIPAttempts bounds attempts from one client address. Account and
	// password limits use separate hash-keyed buckets in the same window.
	RateLimitIPAttempts       int
	RateLimitAccountAttempts  int
	RateLimitPasswordAttempts int
	RateLimitWindow           time.Duration
	// RateLimitStore overrides the host-registered or default memory store.
	RateLimitStore authcontracts.RateLimitStore
	// EnableCSRF verifies Origin/Referer on every state-changing Authkit route.
	// TrustedOrigins allows explicitly configured cross-origin browser clients.
	EnableCSRF     bool
	TrustedOrigins []string
	// EnableUserManagement registers the /users CRUD endpoints.
	EnableUserManagement bool
	// EnableAuditLog wires the audit service into the controllers.
	EnableAuditLog bool
	// UserManagementRoles gates the /users endpoints behind a RequireRole check:
	// the authenticated user's role must be one of these. It defaults to
	// []string{"admin"} (fail-closed) so /users is admin-only out of the box; the
	// single-admin bootstrap still works because auth:create-user mints an admin.
	// When EnableUserManagement is true the gate is ALWAYS mounted — an empty list
	// falls back to []string{"admin"} rather than leaving /users ungated.
	UserManagementRoles []string
	// Roles, when non-empty, is the set of role values accepted when creating or
	// updating a user (the management endpoints reject anything outside it).
	// Empty means any role is accepted. The frontend renders these as a select.
	Roles []string
	// EnableTwoFactor registers the TOTP two-factor endpoints and the two-step
	// login gate. Each user still opts in individually by enrolling.
	EnableTwoFactor bool
	// TwoFactorIssuer is the issuer shown in the authenticator app (defaults to
	// the package issuer when empty).
	TwoFactorIssuer string
	// RecoveryCodeCount is how many recovery codes are generated on confirmation.
	RecoveryCodeCount int
	// EnableRememberMe enables the persistent "remember me" login cookie (the
	// login endpoint honours a `remember` flag; a guarded middleware re-logs the
	// user in from the cookie when the session has expired).
	EnableRememberMe bool
	// RememberLifetime is how long a remember cookie stays valid (sliding on use).
	RememberLifetime time.Duration
	// EnableSessions enables active-session tracking: the /sessions endpoints, the
	// login-history endpoint, and the TrackSession middleware (terminated sessions
	// are rejected on their next request).
	EnableSessions bool
	// EnableAPITokens mounts session-only token management endpoints and allows
	// ProtectToken/ProtectAny to authenticate this guard's opaque bearer tokens.
	// It is off by default.
	EnableAPITokens bool
	// APITokenAllowedScopes is the allow-list users may assign to tokens. An empty
	// list permits only unscoped tokens.
	APITokenAllowedScopes   []string
	APITokenDefaultLifetime time.Duration
	APITokenMaxLifetime     time.Duration
	APITokenMaxPerUser      int
	// KeepAPITokensOnPasswordChange opts out of secure default revocation.
	KeepAPITokensOnPasswordChange bool
	// SessionActiveWindow is how recently a session must have been active to be
	// listed (defaults to the configured session lifetime).
	SessionActiveWindow time.Duration
	// UsersTable / AuditTable / RememberTokensTable / SessionsTable bind this
	// instance's repositories to specific tables, so two authkit instances can run
	// over disjoint user domains (e.g. "accounts" and "admin_users") in one app.
	// Empty values fall back to the package defaults ("users", "audit_logs",
	// "auth_remember_tokens", "auth_sessions"), reproducing single-instance behaviour.
	UsersTable          string
	AuditTable          string
	RememberTokensTable string
	SessionsTable       string
	APITokensTable      string
	// RememberCookieName is the name of this instance's persistent "remember me"
	// cookie. Two instances on one origin must differ here so their cookies don't
	// overwrite each other. Empty falls back to the package default ("authkit_remember").
	RememberCookieName string
	// EnableImpersonation mounts the impersonation endpoints (POST /auth/impersonate
	// and /auth/impersonate/stop) and the reject-while-impersonating guards. Off by
	// default. Who may impersonate whom is decided by the config gate below plus an
	// optional host hook (authkit.RegisterImpersonationPolicy).
	EnableImpersonation bool
	// ImpersonationRoles: the actor must hold one of these roles to impersonate
	// (empty = any authenticated user in this guard).
	ImpersonationRoles []string
	// ImpersonationTargetGuards: the guards this guard's actors may impersonate into
	// ("*" = any; include this guard's own name for same-guard). Empty = this guard
	// cannot impersonate (it may still be a target of another guard).
	ImpersonationTargetGuards []string
	// ImpersonationProtectedRoles: target users holding one of these roles can never
	// be impersonated.
	ImpersonationProtectedRoles []string
}

// DefaultOptions returns the baked-in defaults (matches the published config).
func DefaultOptions() Options {
	return Options{
		Prefix:                    "/api/v1",
		Guard:                     "admin",
		MinPasswordLength:         services.DefaultMinPasswordLength,
		RateLimitIPAttempts:       20,
		RateLimitAccountAttempts:  5,
		RateLimitPasswordAttempts: 5,
		RateLimitWindow:           time.Minute,
		EnableCSRF:                true,
		EnableUserManagement:      true,
		UserManagementRoles:       []string{services.AdminRole},
		EnableAuditLog:            true,
		EnableTwoFactor:           true,
		RecoveryCodeCount:         services.DefaultRecoveryCodeCount,
		EnableRememberMe:          true,
		RememberLifetime:          services.DefaultRememberLifetime,
		EnableSessions:            true,
		SessionActiveWindow:       services.DefaultSessionActiveWindow,
		APITokenDefaultLifetime:   services.DefaultAPITokenLifetime,
		APITokenMaxLifetime:       services.DefaultMaxAPITokenLifetime,
		APITokenMaxPerUser:        services.DefaultMaxAPITokensPerUser,
	}
}

// OptionsFromConfig builds Options from the published authkit.* config, falling
// back to DefaultOptions for any unset key.
func OptionsFromConfig() Options {
	o := DefaultOptions()
	cfg := facades.Config()
	if cfg == nil {
		return o
	}
	if v := cfg.GetString("authkit.route_prefix"); v != "" {
		o.Prefix = v
	}
	if v := cfg.GetString("authkit.guard"); v != "" {
		o.Guard = v
	}
	if v := cfg.GetInt("authkit.min_password_length"); v > 0 {
		o.MinPasswordLength = v
	}
	if v := cfg.GetInt("authkit.rate_limit.ip_attempts"); v > 0 {
		o.RateLimitIPAttempts = v
	}
	if v := cfg.GetInt("authkit.rate_limit.account_attempts"); v > 0 {
		o.RateLimitAccountAttempts = v
	}
	if v := cfg.GetInt("authkit.rate_limit.password_attempts"); v > 0 {
		o.RateLimitPasswordAttempts = v
	}
	if v := cfg.GetInt("authkit.rate_limit.window"); v > 0 {
		o.RateLimitWindow = time.Duration(v) * time.Second
	}
	o.EnableUserManagement = cfg.GetBool("authkit.features.user_management", o.EnableUserManagement)
	o.EnableAuditLog = cfg.GetBool("authkit.features.audit_log", o.EnableAuditLog)
	o.EnableTwoFactor = cfg.GetBool("authkit.features.two_factor", o.EnableTwoFactor)
	o.EnableRememberMe = cfg.GetBool("authkit.features.remember_me", o.EnableRememberMe)
	if v := cfg.GetInt("authkit.remember.lifetime_days"); v > 0 {
		o.RememberLifetime = time.Duration(v) * 24 * time.Hour
	}
	o.EnableSessions = cfg.GetBool("authkit.features.sessions", o.EnableSessions)
	o.EnableAPITokens = cfg.GetBool("authkit.features.api_tokens", o.EnableAPITokens)
	o.APITokenAllowedScopes = toStringSlice(cfg.Get("authkit.api_tokens.allowed_scopes"))
	if v := cfg.GetInt("authkit.api_tokens.default_lifetime_days"); v > 0 {
		o.APITokenDefaultLifetime = time.Duration(v) * 24 * time.Hour
	}
	if v := cfg.GetInt("authkit.api_tokens.max_lifetime_days"); v > 0 {
		o.APITokenMaxLifetime = time.Duration(v) * 24 * time.Hour
	}
	if v := cfg.GetInt("authkit.api_tokens.max_per_user"); v > 0 {
		o.APITokenMaxPerUser = v
	}
	o.KeepAPITokensOnPasswordChange = !cfg.GetBool("authkit.api_tokens.revoke_on_password_change", true)
	o.EnableCSRF = cfg.GetBool("authkit.csrf.enabled", o.EnableCSRF)
	o.TrustedOrigins = toStringSlice(cfg.Get("authkit.csrf.trusted_origins"))
	// The active-session window mirrors the session lifetime so the list hides
	// sessions whose store entry has already expired.
	if v := cfg.GetInt("session.lifetime"); v > 0 {
		o.SessionActiveWindow = time.Duration(v) * time.Minute
	}
	if v := cfg.GetString("authkit.two_factor.issuer"); v != "" {
		o.TwoFactorIssuer = v
	}
	if v := cfg.GetInt("authkit.two_factor.recovery_codes"); v > 0 {
		o.RecoveryCodeCount = v
	}
	if v := cfg.Get("authkit.user_management_roles"); v != nil {
		o.UserManagementRoles = toStringSlice(v)
	}
	if v := cfg.Get("authkit.roles"); v != nil {
		o.Roles = toStringSlice(v)
	}
	o.UsersTable = cfg.GetString("authkit.tables.users")
	o.AuditTable = cfg.GetString("authkit.tables.audit")
	o.RememberTokensTable = cfg.GetString("authkit.tables.remember_tokens")
	o.SessionsTable = cfg.GetString("authkit.tables.sessions")
	o.APITokensTable = cfg.GetString("authkit.tables.api_tokens")
	o.RememberCookieName = cfg.GetString("authkit.remember.cookie_name")
	o.EnableImpersonation = cfg.GetBool("authkit.impersonation.enabled", o.EnableImpersonation)
	o.ImpersonationRoles = toStringSlice(cfg.Get("authkit.impersonation.roles"))
	o.ImpersonationTargetGuards = toStringSlice(cfg.Get("authkit.impersonation.target_guards"))
	o.ImpersonationProtectedRoles = toStringSlice(cfg.Get("authkit.impersonation.protected_roles"))
	return o
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

// Register wires the package services + controllers and mounts the routes onto
// router. router is typically facades.Route(). Zero-valued Options fields fall
// back to DefaultOptions so a bare Register(router, Options{}) is safe.
func Register(router route.Router, opts Options) {
	def := DefaultOptions()
	if opts.Prefix == "" {
		opts.Prefix = def.Prefix
	}
	if opts.Guard == "" {
		opts.Guard = def.Guard
	}
	if opts.MinPasswordLength <= 0 {
		opts.MinPasswordLength = def.MinPasswordLength
	}
	if opts.RateLimitIPAttempts <= 0 {
		opts.RateLimitIPAttempts = def.RateLimitIPAttempts
	}
	if opts.RateLimitAccountAttempts <= 0 {
		opts.RateLimitAccountAttempts = def.RateLimitAccountAttempts
	}
	if opts.RateLimitPasswordAttempts <= 0 {
		opts.RateLimitPasswordAttempts = def.RateLimitPasswordAttempts
	}
	if opts.RateLimitWindow <= 0 {
		opts.RateLimitWindow = def.RateLimitWindow
	}
	if opts.APITokenDefaultLifetime <= 0 {
		opts.APITokenDefaultLifetime = def.APITokenDefaultLifetime
	}
	if opts.APITokenMaxLifetime <= 0 {
		opts.APITokenMaxLifetime = def.APITokenMaxLifetime
	}
	if opts.APITokenMaxPerUser <= 0 {
		opts.APITokenMaxPerUser = def.APITokenMaxPerUser
	}
	// Fail-closed: /users is always gated. An empty management-role list falls
	// back to the admin role rather than leaving the endpoints open.
	managementRoles := opts.UserManagementRoles
	if len(managementRoles) == 0 {
		managementRoles = []string{services.AdminRole}
	}

	usersRepo := repositories.NewUsersWithTable(opts.UsersTable)
	rateLimitStore := opts.RateLimitStore
	if rateLimitStore == nil {
		rateLimitStore = authcontracts.RegisteredRateLimitStore()
	}
	if rateLimitStore == nil {
		rateLimitStore = middleware.DefaultRateLimitStore()
	}
	attemptLimiter := middleware.NewAttemptLimiter(rateLimitStore, "authkit:"+opts.Guard, opts.RateLimitWindow)
	hasher := services.NewFacadeHasher()
	authSvc := services.NewAuth(usersRepo, hasher, opts.MinPasswordLength)

	var auditSvc *services.Audit
	if opts.EnableAuditLog {
		auditSvc = services.NewAudit(repositories.NewAuditWithTable(opts.AuditTable))
	}

	var twoFactorSvc *services.TwoFactor
	if opts.EnableTwoFactor {
		twoFactorSvc = services.NewTwoFactor(usersRepo, services.NewFacadeCrypter(), opts.TwoFactorIssuer, opts.RecoveryCodeCount)
	}

	var apiTokensSvc *services.APITokens
	if opts.EnableAPITokens {
		apiTokensSvc = services.NewAPITokens(repositories.NewAPITokensWithTable(opts.APITokensTable), usersRepo, hasher, twoFactorSvc, opts.APITokenAllowedScopes, opts.APITokenMaxLifetime, opts.APITokenMaxPerUser)
	}
	usersSvc := services.NewUsers(usersRepo, hasher, opts.MinPasswordLength, opts.Roles, managementRoles, apiTokensSvc, !opts.KeepAPITokensOnPasswordChange)

	var rememberSvc *services.Remember
	if opts.EnableRememberMe {
		rememberSvc = services.NewRemember(repositories.NewRememberWithTable(opts.RememberTokensTable), opts.RememberLifetime)
	}

	var sessionsSvc *services.Sessions
	if opts.EnableSessions {
		sessionsSvc = services.NewSessions(repositories.NewSessionsWithTable(opts.SessionsTable), opts.SessionActiveWindow)
	}

	authCtrl := controllers.NewAuthController(authSvc, auditSvc, twoFactorSvc, rememberSvc, sessionsSvc, apiTokensSvc, !opts.KeepAPITokensOnPasswordChange, opts.Guard, opts.RememberCookieName, attemptLimiter, opts.RateLimitAccountAttempts, opts.RateLimitPasswordAttempts)
	usersCtrl := controllers.NewUsersController(usersSvc, auditSvc)
	twoFactorCtrl := controllers.NewTwoFactorController(usersSvc, authSvc, twoFactorSvc, auditSvc, rememberSvc, sessionsSvc, opts.Guard, opts.RememberCookieName, attemptLimiter, opts.RateLimitAccountAttempts)
	sessionsCtrl := controllers.NewSessionsController(sessionsSvc, auditSvc, opts.Guard)
	var apiTokenMeta *responses.APITokenMeta
	if opts.EnableAPITokens {
		allowedScopes := opts.APITokenAllowedScopes
		if allowedScopes == nil {
			allowedScopes = []string{}
		}
		apiTokenMeta = &responses.APITokenMeta{
			AllowedScopes:       allowedScopes,
			DefaultLifetimeDays: int(opts.APITokenDefaultLifetime / (24 * time.Hour)),
			MaxLifetimeDays:     int(opts.APITokenMaxLifetime / (24 * time.Hour)),
			MaxPerUser:          opts.APITokenMaxPerUser,
		}
	}
	metaCtrl := controllers.NewMetaController(opts.Roles, opts.MinPasswordLength, responses.MetaFeatures{
		UserManagement: opts.EnableUserManagement,
		TwoFactor:      opts.EnableTwoFactor,
		AuditLog:       opts.EnableAuditLog,
		Sessions:       opts.EnableSessions,
		Impersonation:  opts.EnableImpersonation,
		APITokens:      opts.EnableAPITokens,
	}, apiTokenMeta)
	var apiTokensCtrl *controllers.APITokensController
	if apiTokensSvc != nil {
		apiTokensCtrl = controllers.NewAPITokensController(apiTokensSvc, auditSvc, attemptLimiter, opts.RateLimitPasswordAttempts)
	}

	// Impersonation: build the controller with a guard -> users-table map (so a
	// target in ANY configured guard can be loaded) and this guard's authorization
	// gate. The gate is fail-closed: with no target_guards, this guard cannot
	// impersonate (it may still be a target of another guard).
	var impersonationCtrl *controllers.ImpersonationController
	if opts.EnableImpersonation {
		guardTables := map[string]string{opts.Guard: opts.UsersTable}
		for _, g := range GuardOptions() {
			guardTables[g.Guard] = g.UsersTable
		}
		gate := services.NewImpersonation(opts.ImpersonationRoles, opts.ImpersonationTargetGuards, opts.ImpersonationProtectedRoles)
		impersonationCtrl = controllers.NewImpersonationController(opts.Guard, guardTables, gate, auditSvc)
	}

	// All package routes live under a single owned namespace ({prefix}/auth/*) so
	// they never collide with the host app's own routes (its /meta, /users, …).
	// One outer prefixed group, with nested middleware groups for the three
	// access tiers (public / rate-limited / session-guarded) — Goravel composes
	// nested groups and their middleware natively.
	//
	// StartSession is mounted here (not globally) so the package owns the session
	// for its whole /auth branch — login, the 2FA challenge and the guarded routes
	// all need it. Carrying it on the group avoids starting a session on the app's
	// stateless endpoints. It is idempotent, so a leftover global StartSession is
	// harmless.
	authMiddleware := []contractshttp.Middleware{sessionmiddleware.StartSession()}
	if opts.EnableCSRF {
		authMiddleware = append(authMiddleware, middleware.VerifyRequestOrigin(opts.TrustedOrigins))
	}
	authGroup := router.Prefix(opts.Prefix + "/auth").Middleware(authMiddleware...)
	authGroup.Group(func(r route.Router) {
		// Public, non-sensitive config for the frontend (role options, features).
		r.Get("/meta", metaCtrl.Show)

		// Public but rate-limited: login + the 2FA challenge (gate on session/IP,
		// not on the authenticated guard).
		r.Middleware(middleware.RateLimitByIP(attemptLimiter, opts.RateLimitIPAttempts)).
			Group(func(pub route.Router) {
				pub.Post("/login", authCtrl.Login)
				if opts.EnableTwoFactor {
					pub.Post("/two-factor-challenge", twoFactorCtrl.Challenge)
				}
			})

		// Guarded: everything behind the session guard. When remember-me is on,
		// RememberLogin runs first so an expired session is silently restored from
		// a valid remember cookie before Authenticated checks for a live session.
		guarded := make([]contractshttp.Middleware, 0, 3)
		if rememberSvc != nil {
			guarded = append(guarded, middleware.RememberLogin(opts.Guard, opts.RememberCookieName, usersRepo, rememberSvc, auditSvc, sessionsSvc))
		}
		guarded = append(guarded, middleware.Authenticated(opts.Guard, usersRepo))
		if sessionsSvc != nil {
			// After Authenticated: refresh the current session row and reject it if
			// it was terminated elsewhere.
			guarded = append(guarded, middleware.TrackSession(opts.Guard, sessionsSvc))
		}
		r.Middleware(guarded...).Group(func(g route.Router) {
			g.Post("/logout", authCtrl.Logout)
			g.Get("/me", authCtrl.Me)
			g.Put("/me", authCtrl.UpdateProfile)
			if opts.EnableImpersonation {
				// An actor acting "as" a user must not change that user's password.
				g.Middleware(middleware.RejectWhileImpersonating(opts.Guard), middleware.RateLimitByIP(attemptLimiter, opts.RateLimitIPAttempts)).Put("/password", authCtrl.ChangePassword)
			} else {
				g.Middleware(middleware.RateLimitByIP(attemptLimiter, opts.RateLimitIPAttempts)).Put("/password", authCtrl.ChangePassword)
			}

			if auditSvc != nil {
				g.Get("/logins", authCtrl.LoginHistory)
			}
			if sessionsSvc != nil {
				g.Get("/sessions", sessionsCtrl.Index)
				g.Delete("/sessions", sessionsCtrl.DestroyOthers)
				g.Delete("/sessions/{id}", sessionsCtrl.Destroy)
			}

			if opts.EnableTwoFactor {
				g.Post("/two-factor", twoFactorCtrl.Enable)
				g.Post("/two-factor/confirm", twoFactorCtrl.Confirm)
				g.Delete("/two-factor", twoFactorCtrl.Disable)
				g.Get("/two-factor/recovery-codes", twoFactorCtrl.RecoveryCodes)
				g.Post("/two-factor/recovery-codes", twoFactorCtrl.RegenerateRecoveryCodes)
			}

			if apiTokensCtrl != nil {
				tokenRoutes := g
				if opts.EnableImpersonation {
					tokenRoutes = g.Middleware(middleware.RejectWhileImpersonating(opts.Guard))
				}
				tokenRoutes.Get("/api-tokens", apiTokensCtrl.Index)
				tokenRoutes.Middleware(middleware.RateLimitByIP(attemptLimiter, opts.RateLimitIPAttempts)).Post("/api-tokens", apiTokensCtrl.Store)
				tokenRoutes.Delete("/api-tokens", apiTokensCtrl.DestroyAll)
				tokenRoutes.Delete("/api-tokens/{id}", apiTokensCtrl.Destroy)
			}

			if opts.EnableImpersonation {
				// Start is blocked while already impersonating (no nesting); stop must
				// stay reachable from the impersonated session, so it is left ungated.
				g.Middleware(middleware.RejectWhileImpersonating(opts.Guard)).Post("/impersonate", impersonationCtrl.Start)
				g.Post("/impersonate/stop", impersonationCtrl.Stop)
			}

			if opts.EnableUserManagement {
				// Fail-closed: the whole /users block (reads and writes) is always
				// mounted behind the RequireRole gate using the effective management
				// roles, so no /users endpoint is reachable by a non-admin.
				userMw := make([]contractshttp.Middleware, 0, 2)
				if opts.EnableImpersonation {
					// An actor acting "as" a user must not manage users as them.
					userMw = append(userMw, middleware.RejectWhileImpersonating(opts.Guard))
				}
				userMw = append(userMw, middleware.RequireRole(opts.Guard, usersRepo, managementRoles...))
				g.Middleware(userMw...).Group(func(ur route.Router) {
					ur.Get("/users", usersCtrl.Index)
					ur.Post("/users", usersCtrl.Store)
					ur.Get("/users/{id}", usersCtrl.Show)
					ur.Put("/users/{id}", usersCtrl.Update)
					ur.Delete("/users/{id}", usersCtrl.Destroy)
					ur.Post("/users/{id}/password", usersCtrl.SetPassword)
				})
			}
		})
	})
}
