package config

import (
	"goravel/app/facades"
)

func init() {
	config := facades.Config()
	config.Add("auth", map[string]any{
		// goravel-authkit uses a session guard named "admin" (config authkit.guard).
		"defaults": map[string]any{
			"guard": "admin",
		},

		// The "admin" guard is session-backed (httpOnly cookie) over the orm
		// user provider — this is what the package logs users into.
		"guards": map[string]any{
			"admin": map[string]any{
				"driver":   "session",
				"provider": "user",
			},
		},

		"providers": map[string]any{
			"user": map[string]any{
				"driver": "orm",
			},
		},
	})
}
