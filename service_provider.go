// Package auth is the root of the goravel-auth package: a batteries-included,
// session-based authentication + user-management module for Goravel apps.
//
// A consuming app installs it with `./artisan package:install
// github.com/freshost/goravel-auth`, which registers ServiceProvider into the
// app's provider list. The app then wires the package routes via
// routes.Register and appends migrations.Migrations() to its migration
// registry. Behaviour is tuned via the optional authkit.* config (see README).
package auth

import (
	"github.com/goravel/framework/contracts/binding"
	"github.com/goravel/framework/contracts/console"
	"github.com/goravel/framework/contracts/foundation"

	"github.com/freshost/goravel-auth/console/commands"
)

// Name is the human-readable module name.
const Name = "Auth"

// App holds the application instance for package-internal resolution.
var App foundation.Application

// ServiceProvider registers the goravel-auth artisan commands and boots the
// package. Route + migration wiring is explicit in the consuming app (see
// routes.Register and migrations.Migrations).
type ServiceProvider struct{}

// Relationship declares the framework services the package depends on so it
// boots after them. It provides no container bindings of its own.
func (r *ServiceProvider) Relationship() binding.Relationship {
	return binding.Relationship{
		Bindings: []string{},
		Dependencies: []string{
			binding.Config,
			binding.Orm,
			binding.Hash,
			binding.Auth,
		},
		ProvideFor: []string{},
	}
}

// Register stores the application instance.
func (r *ServiceProvider) Register(app foundation.Application) {
	App = app
}

// Boot registers the package artisan commands.
func (r *ServiceProvider) Boot(app foundation.Application) {
	app.Commands([]console.Command{
		commands.NewCreateUser(),
	})
}
