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
			// isn't tripped by the per-IP limiter.
			"attempts": config.Env("AUTHKIT_RATE_LIMIT_ATTEMPTS", 5),
			"window":   60,
		},
		"features": map[string]any{
			"user_management": true,
			"audit_log":       true,
			"two_factor":      true,
			"remember_me":     true,
			"sessions":        true,
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
				"remember_cookie_name":  "authkit_remember",
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
