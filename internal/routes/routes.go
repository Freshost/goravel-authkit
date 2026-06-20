// Package routes registers the goravel-auth HTTP endpoints onto a consuming
// app's router. The app calls Register from its own routes file so the package
// controllers land in the app's import graph (required for `swag` to scan their
// annotations into the OpenAPI contract).
package routes

import (
	"time"

	"github.com/goravel/framework/contracts/route"
	"github.com/goravel/framework/facades"

	"github.com/freshost/goravel-auth/internal/http/controllers"
	"github.com/freshost/goravel-auth/internal/http/middleware"
	"github.com/freshost/goravel-auth/internal/repositories"
	"github.com/freshost/goravel-auth/internal/services"
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
	// RateLimitAttempts / RateLimitWindow bound the login endpoint per IP.
	RateLimitAttempts int
	RateLimitWindow   time.Duration
	// EnableUserManagement registers the /users CRUD endpoints.
	EnableUserManagement bool
	// EnableAuditLog wires the audit service into the controllers.
	EnableAuditLog bool
	// UserManagementRoles, when non-empty, gates the /users endpoints behind a
	// RequireRole check (the user's role must be one of these). Empty (the v1
	// default) leaves them open to any authenticated user, since v1 ships no
	// RBAC. Set e.g. []string{"admin"} once your app assigns roles.
	UserManagementRoles []string
}

// DefaultOptions returns the baked-in defaults (matches the published config).
func DefaultOptions() Options {
	return Options{
		Prefix:               "/api/v1",
		Guard:                "admin",
		MinPasswordLength:    services.DefaultMinPasswordLength,
		RateLimitAttempts:    5,
		RateLimitWindow:      time.Minute,
		EnableUserManagement: true,
		EnableAuditLog:       true,
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
	if v := cfg.GetInt("authkit.rate_limit.attempts"); v > 0 {
		o.RateLimitAttempts = v
	}
	if v := cfg.GetInt("authkit.rate_limit.window"); v > 0 {
		o.RateLimitWindow = time.Duration(v) * time.Second
	}
	o.EnableUserManagement = cfg.GetBool("authkit.features.user_management", o.EnableUserManagement)
	o.EnableAuditLog = cfg.GetBool("authkit.features.audit_log", o.EnableAuditLog)
	if v := cfg.Get("authkit.user_management_roles"); v != nil {
		o.UserManagementRoles = toStringSlice(v)
	}
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
	if opts.RateLimitAttempts <= 0 {
		opts.RateLimitAttempts = def.RateLimitAttempts
	}
	if opts.RateLimitWindow <= 0 {
		opts.RateLimitWindow = def.RateLimitWindow
	}

	usersRepo := repositories.NewUsers()
	hasher := services.NewFacadeHasher()
	authSvc := services.NewAuth(usersRepo, hasher, opts.MinPasswordLength)
	usersSvc := services.NewUsers(usersRepo, hasher, opts.MinPasswordLength)

	var auditSvc *services.Audit
	if opts.EnableAuditLog {
		auditSvc = services.NewAudit(repositories.NewAudit())
	}

	authCtrl := controllers.NewAuthController(authSvc, auditSvc, opts.Guard)
	usersCtrl := controllers.NewUsersController(usersSvc, auditSvc)

	// Public: login (rate-limited).
	router.Prefix(opts.Prefix + "/auth").
		Middleware(middleware.RateLimitAuth(opts.RateLimitAttempts, opts.RateLimitWindow)).
		Group(func(r route.Router) {
			r.Post("/login", authCtrl.Login)
		})

	// Guarded: everything behind the session guard.
	router.Prefix(opts.Prefix).
		Middleware(middleware.Authenticated(opts.Guard)).
		Group(func(r route.Router) {
			r.Post("/auth/logout", authCtrl.Logout)
			r.Get("/auth/me", authCtrl.Me)
			r.Put("/auth/password", authCtrl.ChangePassword)

			if opts.EnableUserManagement {
				userRoutes := func(ur route.Router) {
					ur.Get("/users", usersCtrl.Index)
					ur.Post("/users", usersCtrl.Store)
					ur.Get("/users/{id}", usersCtrl.Show)
					ur.Put("/users/{id}", usersCtrl.Update)
					ur.Delete("/users/{id}", usersCtrl.Destroy)
					ur.Post("/users/{id}/password", usersCtrl.SetPassword)
				}
				if len(opts.UserManagementRoles) > 0 {
					r.Middleware(middleware.RequireRole(opts.Guard, opts.UserManagementRoles...)).Group(userRoutes)
				} else {
					userRoutes(r)
				}
			}
		})
}
