package routes

import (
	"sort"
	"time"

	"github.com/google/uuid"
	contractshttp "github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/contracts/route"
	"github.com/goravel/framework/facades"
	sessionmiddleware "github.com/goravel/framework/session/middleware"

	"github.com/freshost/goravel-authkit/helpers"
	"github.com/freshost/goravel-authkit/http/middleware"
	"github.com/freshost/goravel-authkit/repositories"
)

// GuardsKey is the config path under which an app declares its authkit guards.
// Each child key is a guard name — one self-contained auth domain: its route
// prefix, user table, session guard, audit/remember/session tables, remember
// cookie and feature overrides:
//
//	config.Add("authkit", map[string]any{
//	    "guards": map[string]any{
//	        "client": map[string]any{"prefix": "/api/v1", "users_table": "accounts"},
//	        "admin":  map[string]any{"prefix": "/api/admin/v1", "users_table": "admin_users"},
//	    },
//	})
//
// When present, the ServiceProvider auto-registers a Goravel session guard and the
// migrations for each guard's tables, and RegisterAll mounts every guard's routes —
// so the app declares its auth domains in one place and authkit wires the tables,
// migrations, Goravel guards and routes itself.
const GuardsKey = "authkit.guards"

// HasGuardsConfig reports whether the app declared guards under authkit.guards
// (multi-guard mode). When false authkit runs a single guard built from the
// legacy top-level authkit.* config (single-guard mode).
func HasGuardsConfig() bool {
	return len(guardConfigNames()) > 0
}

// guardConfigNames returns the declared guard names, sorted for deterministic
// ordering (guard registration, migration order, default guard).
func guardConfigNames() []string {
	cfg := facades.Config()
	if cfg == nil {
		return nil
	}
	raw, ok := cfg.Get(GuardsKey).(map[string]any)
	if !ok || len(raw) == 0 {
		return nil
	}
	names := make([]string, 0, len(raw))
	for name := range raw {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// GuardOptions returns the Options for every authkit guard: one per entry under
// authkit.guards, or a single entry from the legacy top-level authkit.* config
// when authkit.guards is absent. It is the single list the ServiceProvider (guard
// + migration registration) and RegisterAll (routes) both iterate, so the two
// modes stay consistent.
func GuardOptions() []Options {
	names := guardConfigNames()
	if len(names) == 0 {
		return []Options{OptionsFromConfig()}
	}
	opts := make([]Options, 0, len(names))
	for _, name := range names {
		opts = append(opts, OptionsForGuard(name))
	}
	return opts
}

// OptionsForGuard builds the Options for one declared guard. It starts from the
// global authkit.* defaults (password policy, rate limit, features, roles), then
// applies the guard's overrides, deriving the table names and remember cookie from
// the guard name when they are not given:
//
//	users_table           default "<name>_users"
//	audit_table           default "<name>_audit_logs"
//	remember_tokens_table default "<name>_remember_tokens"
//	sessions_table        default "<name>_auth_sessions"
//	remember_cookie_name  default "authkit_<name>_remember"
func OptionsForGuard(name string) Options {
	o := OptionsFromConfig()
	o.Guard = name

	cfg := facades.Config()
	if cfg == nil {
		return o
	}
	base := GuardsKey + "." + name + "."

	o.Prefix = cfg.GetString(base+"prefix", o.Prefix)
	o.UsersTable = cfg.GetString(base+"users_table", name+"_users")
	o.AuditTable = cfg.GetString(base+"audit_table", name+"_audit_logs")
	o.RememberTokensTable = cfg.GetString(base+"remember_tokens_table", name+"_remember_tokens")
	o.SessionsTable = cfg.GetString(base+"sessions_table", name+"_auth_sessions")
	o.RememberCookieName = cfg.GetString(base+"remember_cookie_name", "authkit_"+name+"_remember")

	if v := cfg.Get(base + "roles"); v != nil {
		o.Roles = toStringSlice(v)
	}
	if v := cfg.Get(base + "user_management_roles"); v != nil {
		o.UserManagementRoles = toStringSlice(v)
	}
	if v := cfg.GetInt(base + "min_password_length"); v > 0 {
		o.MinPasswordLength = v
	}
	if v := cfg.GetInt(base + "rate_limit.attempts"); v > 0 {
		o.RateLimitAttempts = v
	}
	if v := cfg.GetInt(base + "rate_limit.window"); v > 0 {
		o.RateLimitWindow = time.Duration(v) * time.Second
	}
	if v := cfg.GetString(base + "two_factor.issuer"); v != "" {
		o.TwoFactorIssuer = v
	}
	if v := cfg.GetInt(base + "two_factor.recovery_codes"); v > 0 {
		o.RecoveryCodeCount = v
	}
	if v := cfg.GetInt(base + "remember.lifetime_days"); v > 0 {
		o.RememberLifetime = time.Duration(v) * 24 * time.Hour
	}

	// Impersonation: enabling is global (authkit.impersonation.enabled, inherited
	// above); the gate (who/where/protected) is per guard.
	if v := cfg.Get(base + "impersonation.roles"); v != nil {
		o.ImpersonationRoles = toStringSlice(v)
	}
	if v := cfg.Get(base + "impersonation.target_guards"); v != nil {
		o.ImpersonationTargetGuards = toStringSlice(v)
	}
	if v := cfg.Get(base + "impersonation.protected_roles"); v != nil {
		o.ImpersonationProtectedRoles = toStringSlice(v)
	}

	// Per-guard feature overrides default to the global feature flag.
	o.EnableUserManagement = cfg.GetBool(base+"features.user_management", o.EnableUserManagement)
	o.EnableAuditLog = cfg.GetBool(base+"features.audit_log", o.EnableAuditLog)
	o.EnableTwoFactor = cfg.GetBool(base+"features.two_factor", o.EnableTwoFactor)
	o.EnableRememberMe = cfg.GetBool(base+"features.remember_me", o.EnableRememberMe)
	o.EnableSessions = cfg.GetBool(base+"features.sessions", o.EnableSessions)

	return o
}

// RegisterAll mounts every authkit guard (authkit.guards, or the single default
// guard when none are declared). A single-domain app keeps working unchanged with
// the same one-liner.
func RegisterAll(router route.Router) {
	for _, o := range GuardOptions() {
		Register(router, o)
	}
}

// optionsByGuard returns the resolved Options for a configured guard, matching how
// that guard was actually registered (so single-guard mode resolves the default
// "users" table, not the multi-guard "<name>_users" convention).
func optionsByGuard(name string) Options {
	for _, o := range GuardOptions() {
		if o.Guard == name {
			return o
		}
	}
	return OptionsForGuard(name)
}

// Protect returns the middleware chain that guards the HOST's own routes behind
// the named authkit guard: it starts the session and authenticates the request
// against that guard's user table. Apply it to a route group:
//
//	facades.Route().Prefix("/api/v1").Middleware(authkitroutes.Protect("client")...).
//	    Group(func(r route.Router) {
//	        r.Get("/invoices", invoices.Index) // requires a logged-in "client" user
//	    })
//
// It is the authkit equivalent of Laravel's `auth:client` route middleware.
func Protect(guard string) []contractshttp.Middleware {
	repo := repositories.NewUsersWithTable(optionsByGuard(guard).UsersTable)
	return []contractshttp.Middleware{
		sessionmiddleware.StartSession(),
		middleware.Authenticated(guard, repo),
	}
}

// ProtectRole is Protect plus a role gate: the authenticated user's role must be
// one of roles. With no roles it behaves like Protect (any authenticated user).
func ProtectRole(guard string, roles ...string) []contractshttp.Middleware {
	repo := repositories.NewUsersWithTable(optionsByGuard(guard).UsersTable)
	return []contractshttp.Middleware{
		sessionmiddleware.StartSession(),
		middleware.Authenticated(guard, repo),
		middleware.RequireRole(guard, repo, roles...),
	}
}

// AuthUserID returns the id of the user authenticated by Protect/ProtectRole on
// the current request, or uuid.Nil when there is none. Read it inside your own
// protected handlers to scope queries to the current user.
func AuthUserID(ctx contractshttp.Context) uuid.UUID {
	return helpers.AuthUserID(ctx)
}
