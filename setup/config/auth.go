// This file is published into the consuming app's config/ directory by
// `./artisan package:install github.com/freshost/goravel-auth` (or
// `vendor:publish --tag=authkit`). It defines the session "admin" guard backed
// by the canonical users table that goravel-auth owns.
//
// If your app already has a config/auth.go with other guards, merge this guard
// in by hand instead of overwriting (see the package README / adoption skill).
package config

import "github.com/goravel/framework/facades"

func init() {
	config := facades.Config()
	config.Add("auth", map[string]any{
		// Default guard used when none is specified.
		"defaults": map[string]any{
			"guard": "admin",
		},
		// The "admin" guard uses the session driver (httpOnly cookie) and loads
		// users via the orm provider. Supported drivers: "jwt", "session".
		"guards": map[string]any{
			"admin": map[string]any{
				"driver":   "session",
				"provider": "users",
			},
		},
		// Supported provider drivers: "orm".
		"providers": map[string]any{
			"users": map[string]any{
				"driver": "orm",
			},
		},
	})
}
