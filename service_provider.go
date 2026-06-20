// Package auth is the root of the goravel-auth package: a batteries-included,
// session-based authentication + user-management module for Goravel apps.
//
// Install is a single step:
//
//	./artisan package:install github.com/freshost/goravel-auth
//
// which registers this ServiceProvider and writes the config files
// (config/auth.go, config/authkit.go, config/hashing.go). The provider then
// registers the migrations, the HTTP routes, and the artisan commands itself —
// the consuming app does not wire anything by hand. See the README.
package auth

import (
	"github.com/goravel/framework/contracts/binding"
	"github.com/goravel/framework/contracts/console"
	"github.com/goravel/framework/contracts/foundation"

	"github.com/freshost/goravel-auth/console/commands"
	"github.com/freshost/goravel-auth/migrations"
	"github.com/freshost/goravel-auth/routes"
)

// PackageName is the module path, used as the first argument to Publishes.
const PackageName = "github.com/freshost/goravel-auth"

// Name is the human-readable module name.
const Name = "Auth"

// App holds the application instance for package-internal resolution.
var App foundation.Application

// ServiceProvider registers the goravel-auth migrations, routes, commands, and
// publishable config. Everything is wired here so the consuming app only has to
// register this provider (done automatically by `package:install`).
type ServiceProvider struct{}

// Relationship declares the framework services the package depends on so it
// boots after them. It registers no container bindings of its own.
func (r *ServiceProvider) Relationship() binding.Relationship {
	return binding.Relationship{
		Bindings: []string{},
		Dependencies: []string{
			binding.Config,
			binding.Orm,
			binding.Hash,
			binding.Auth,
			binding.Schema,
			binding.Route,
		},
		ProvideFor: []string{},
	}
}

// Register stores the application instance.
func (r *ServiceProvider) Register(app foundation.Application) {
	App = app
}

// Boot registers everything the package ships: migrations, routes, artisan
// commands, and the publishable config (for `vendor:publish`).
func (r *ServiceProvider) Boot(app foundation.Application) {
	// Migrations — added to the schema registry so `artisan migrate` runs them.
	if schema := app.MakeSchema(); schema != nil {
		schema.Register(migrations.Migrations())
	}

	// Routes — mounted onto the app router from the authkit.* config.
	if router := app.MakeRoute(); router != nil {
		routes.Register(router, routes.OptionsFromConfig())
	}

	// Artisan commands.
	app.Commands([]console.Command{
		commands.NewCreateUser(),
	})

	// Publishable config (the setup.go installer writes these too; this enables
	// `./artisan vendor:publish --tag=authkit` as an alternative).
	app.Publishes(PackageName, map[string]string{
		"setup/config/auth.go":    app.ConfigPath("auth.go"),
		"setup/config/authkit.go": app.ConfigPath("authkit.go"),
		"setup/config/hashing.go": app.ConfigPath("hashing.go"),
	}, "authkit")
}
