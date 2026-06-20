// This file is published into the consuming app's config/ directory by
// `./artisan package:install github.com/freshost/goravel-auth`. Every key is
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
		// Login rate limit: attempts per window (seconds) per client IP.
		"rate_limit": map[string]any{
			"attempts": 5,
			"window":   60,
		},
		// Feature toggles.
		"features": map[string]any{
			// Register the /users admin CRUD endpoints.
			"user_management": true,
			// Write audit entries to the audit_logs table.
			"audit_log": true,
		},
		// Roles allowed to use the /users endpoints. Empty (default) = any
		// authenticated user (v1 has no RBAC). Set e.g. []string{"admin"} once
		// your app assigns roles to gate user management behind a role.
		"user_management_roles": []string{},
	})
}
