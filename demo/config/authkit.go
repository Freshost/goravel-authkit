// goravel-authkit configuration. In a real app `./artisan package:install`
// publishes this file; here it is committed directly. Every key is optional —
// the package falls back to these same defaults if the file is absent.
package config

import "github.com/goravel/framework/facades"

func init() {
	config := facades.Config()
	config.Add("authkit", map[string]any{
		"route_prefix":        "/api/v1",
		"guard":               "admin",
		"min_password_length": 8,
		"rate_limit": map[string]any{
			// Env-overridable so the test suite (many logins in one process/minute)
			// isn't tripped by either limiter dimension.
			"ip_attempts":       config.Env("AUTHKIT_RATE_LIMIT_IP_ATTEMPTS", 20),
			"account_attempts":  config.Env("AUTHKIT_RATE_LIMIT_ACCOUNT_ATTEMPTS", 5),
			"password_attempts": config.Env("AUTHKIT_RATE_LIMIT_PASSWORD_ATTEMPTS", 5),
			"window":            60,
		},
		"csrf": map[string]any{
			"enabled":         true,
			"trusted_origins": []string{},
		},
		"features": map[string]any{
			"user_management": true,
			"audit_log":       true,
			"two_factor":      true,
			"remember_me":     true,
			"sessions":        true,
			"api_tokens":      true,
		},
		"api_tokens": map[string]any{
			"allowed_scopes":            []string{"profile:read", "profile:write"},
			"default_lifetime_days":     30,
			"max_lifetime_days":         365,
			"max_per_user":              20,
			"revoke_on_password_change": true,
		},
		"two_factor": map[string]any{
			"issuer":         "Authkit Demo",
			"recovery_codes": 8,
		},
		"remember": map[string]any{
			"lifetime_days": 30,
		},
		// Fail-closed: /users is admin-only. Always gated; empty falls back to ["admin"].
		"user_management_roles": []string{"admin"},
		"roles":                 []string{"admin", "user"},

		// Impersonation is enabled globally; the per-guard "impersonation" block (see
		// the admin guard below) gates who may impersonate into which guards.
		"impersonation": map[string]any{"enabled": true},

		// Two guards (independent auth domains), declared in one place. authkit
		// auto-registers a Goravel session guard and the migrations for each guard's
		// tables, and routes.RegisterAll mounts them — so config/auth.go and
		// per-guard route wiring are unnecessary. Each guard inherits the password
		// policy, rate limit, features and roles above unless it overrides them.
		//
		//   - "admin"  keeps the default table names (and remember cookie) so the
		//     single-guard defaults are preserved.
		//   - "client" only sets prefix + users_table; its audit/remember/session
		//     tables default to client_* and its remember cookie to authkit_client_remember.
		"guards": map[string]any{
			"admin": map[string]any{
				"prefix":                "/api/v1",
				"users_table":           "users",
				"audit_table":           "audit_logs",
				"remember_tokens_table": "auth_remember_tokens",
				"sessions_table":        "auth_sessions",
				"api_tokens_table":      "api_tokens",
				"remember_cookie_name":  "authkit_remember",
				// Admins may impersonate users in the client portal and in their own
				// guard, but never another admin (protected_roles).
				"impersonation": map[string]any{
					"roles":           []string{"admin"},
					"target_guards":   []string{"client", "admin"},
					"protected_roles": []string{"admin"},
				},
			},
			"client": map[string]any{
				"prefix":      "/api/client/v1",
				"users_table": "client_users",
				// Per-guard overrides: the root min_password_length/features above
				// apply to every guard, but a guard can override them. The client
				// portal requires longer passwords and has 2FA turned off.
				"min_password_length": 12,
				"features": map[string]any{
					"two_factor": false,
				},
			},
		},
	})
}
