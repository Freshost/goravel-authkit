// This file is published into the consuming app's config/ directory by
// `./artisan package:install github.com/freshost/goravel-authkit`. Every key is
// optional — the package falls back to these same defaults if the file is
// absent. Tune as needed; see docs/configuration.md.
package config

import "github.com/goravel/framework/facades"

func init() {
	config := facades.Config()
	config.Add("authkit", map[string]any{
		// Prefix for all package routes.
		"route_prefix": "/api/v1",
		// Goravel session guard name (must match a guard in config/auth.go).
		"guard": "admin",
		// Minimum accepted new-password length.
		"min_password_length": 8,
		// Authentication rate limits. Buckets are combined: a request must pass
		// both its client-IP bucket and its account/user bucket.
		"rate_limit": map[string]any{
			"ip_attempts":       20,
			"account_attempts":  5,
			"password_attempts": 5,
			"window":            60,
		},
		// Fail-closed Origin/Referer verification for every state-changing route.
		// Add exact SPA origins here only when the frontend is cross-origin.
		"csrf": map[string]any{
			"enabled":         true,
			"trusted_origins": []string{},
		},
		// Feature toggles.
		"features": map[string]any{
			// Register the /users admin CRUD endpoints.
			"user_management": true,
			// Write audit entries to the audit_logs table.
			"audit_log": true,
			// Register the TOTP two-factor endpoints + two-step login gate.
			// Users still opt in individually by enrolling.
			"two_factor": true,
			// Persistent "remember me" login cookie (selector-validator token).
			"remember_me": true,
			// Active-session tracking: list/terminate sessions + login history.
			"sessions": true,
			// Personal API tokens are opt-in. When enabled, users can manage
			// expiring, scoped bearer tokens from their account settings.
			"api_tokens": false,
		},
		"api_tokens": map[string]any{
			"allowed_scopes":            []string{},
			"default_lifetime_days":     30,
			"max_lifetime_days":         365,
			"max_per_user":              20,
			"revoke_on_password_change": true,
		},
		// Table overrides for legacy single-guard mode. In multi-guard mode use
		// api_tokens_table inside each guard; it defaults to <guard>_api_tokens.
		"tables": map[string]any{
			"api_tokens": "api_tokens",
		},
		// TOTP two-factor settings.
		"two_factor": map[string]any{
			// Issuer shown in the authenticator app (defaults to "goravel-authkit"
			// when empty).
			"issuer": "",
			// Number of single-use recovery codes generated on confirmation.
			"recovery_codes": 8,
		},
		// "Remember me" settings.
		"remember": map[string]any{
			// How long the remember cookie stays valid, in days (sliding on use).
			"lifetime_days": 30,
		},
		// Roles allowed to use the /users endpoints. Defaults to ["admin"]
		// (fail-closed): /users is admin-only out of the box. The /users routes
		// are ALWAYS gated — an empty list here falls back to ["admin"], never to
		// "any authenticated user". The single-admin bootstrap still works because
		// auth:create-user mints an admin.
		"user_management_roles": []string{"admin"},
		// Assignable role values for users. Empty = any role accepted; set a list
		// to restrict create/update (the backend validates) and to render the
		// role field as a select in the UI (pass the same list to AuthkitProvider).
		"roles": []string{"admin", "user"},
	})
}
