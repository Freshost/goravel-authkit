// Package authkit is the root of the goravel-authkit package: a
// batteries-included, session-based authentication + user-management module for
// Goravel apps.
//
// Install is a single step:
//
//	./artisan package:install github.com/freshost/goravel-authkit
//
// which registers this ServiceProvider and writes the config files
// (config/auth.go, config/authkit.go, config/hashing.go). The provider then
// registers the migrations, the HTTP routes, and the artisan commands itself —
// the consuming app does not wire anything by hand. See the README.
package authkit

import (
	"github.com/goravel/framework/contracts/binding"
	"github.com/goravel/framework/contracts/console"
	"github.com/goravel/framework/contracts/foundation"

	"github.com/freshost/goravel-authkit/commands"
	"github.com/freshost/goravel-authkit/migrations"
	"github.com/freshost/goravel-authkit/routes"
)

// Binding is the service-container key under which the Authkit service is bound;
// the facades.Authkit() accessor resolves it.
const Binding = "authkit"

// PackageName is the module path, used as the first argument to Publishes.
const PackageName = "github.com/freshost/goravel-authkit"

// Name is the human-readable module name.
const Name = "Authkit"

// App holds the application instance, used by the facade to resolve the service.
var App foundation.Application

// ServiceProvider registers the goravel-authkit migrations, routes, commands, and
// publishable config. Everything is wired here so the consuming app only has to
// register this provider (done automatically by `package:install`).
type ServiceProvider struct{}

// Relationship declares the framework services the package depends on so it
// boots after them. It registers no container bindings of its own.
func (r *ServiceProvider) Relationship() binding.Relationship {
	return binding.Relationship{
		Bindings: []string{Binding},
		Dependencies: []string{
			binding.Config,
			binding.Orm,
			binding.Hash,
			binding.Auth,
			binding.Crypt,
			binding.Schema,
			binding.Route,
		},
		ProvideFor: []string{},
	}
}

// Register stores the application instance and binds the Authkit service so
// facades.Authkit() (and any app code) can resolve it.
func (r *ServiceProvider) Register(app foundation.Application) {
	App = app

	app.Bind(Binding, func(app foundation.Application) (any, error) {
		return NewAuthkit(app), nil
	})
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

	// Publishable config — `./artisan vendor:publish --tag=authkit` writes
	// config/authkit.go (the guard + hashing tweaks are applied by setup.go on
	// package:install, not published, so they never clobber the app's files).
	app.Publishes(PackageName, map[string]string{
		"setup/config/authkit.go": app.ConfigPath("authkit.go"),
	}, "authkit")
}
