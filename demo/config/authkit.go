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
		"user_management_roles": []string{},
		"roles":                 []string{"admin", "user"},
	})
}
