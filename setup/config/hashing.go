// This file is published into the consuming app's config/ directory by
// `./artisan package:install github.com/freshost/goravel-auth`. goravel-auth
// hashes passwords through the Hash facade, so the app needs a hashing config
// selecting bcrypt cost 12 — the value that keeps existing $2a$12$ hashes
// verifiable. If your app already configures hashing, ensure it is bcrypt cost
// 12 rather than overwriting.
package config

import "github.com/goravel/framework/facades"

func init() {
	config := facades.Config()
	config.Add("hashing", map[string]any{
		// Supported drivers: "bcrypt", "argon2id".
		"driver": "bcrypt",
		"bcrypt": map[string]any{
			// Cost factor. 12 matches the reference apps and existing hashes.
			"rounds": 12,
		},
		"argon2id": map[string]any{
			"memory":  65536,
			"time":    4,
			"threads": 1,
		},
	})
}
