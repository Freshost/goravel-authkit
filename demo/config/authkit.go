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
			"attempts": 5,
			"window":   60,
		},
		"features": map[string]any{
			"user_management": true,
			"audit_log":       true,
			"two_factor":      true,
		},
		"two_factor": map[string]any{
			"issuer":         "Authkit Demo",
			"recovery_codes": 8,
		},
		"user_management_roles": []string{},
	})
}
