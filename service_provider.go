// Package authkit is the root of the goravel-authkit package: a
// batteries-included, session-based authentication + user-management module for
// Goravel apps.
//
// Install is a single step:
//
//	./artisan package:install github.com/freshost/goravel-authkit
//
// which registers this ServiceProvider and publishes config/authkit.go (and
// config/hashing.go). The app declares its auth domains as guards under
// authkit.guards in config/authkit.go; the provider then auto-registers a Goravel
// session guard and the migrations for each guard (no config/auth.go needed). The
// app mounts the HTTP routes from its own routing callback with one line:
//
//	authkitroutes "github.com/freshost/goravel-authkit/routes"
//	// inside foundation.Setup().WithRouting(func(){ ... })
//	authkitroutes.RegisterAll(facades.Route())
//
// Routes remain an explicit app-side mount so configured dynamic guards are
// registered from the host's routing callback and existing integrations keep a
// stable, duplicate-free contract. The package starts its own session on each
// guard's /auth group, so no global session middleware is required.
//
// See the README and docs/installation.md.
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

// ormProviderName is the Goravel auth provider authkit auto-registers for its
// declared instances (a plain orm provider; authkit loads users from each
// instance's table via its repository, so one shared provider suffices).
const ormProviderName = "authkit_orm"

// PackageName is the module path, used as the first argument to Publishes.
const PackageName = "github.com/freshost/goravel-authkit"

// Name is the human-readable module name.
const Name = "Authkit"

// App holds the application instance, used by the facade to resolve the service.
var App foundation.Application

// ServiceProvider registers the goravel-authkit migrations, commands, and
// publishable config. HTTP routes are mounted app-side via routes.Register (see
// the package doc), preserving Authkit's explicit dynamic-route contract.
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

// Boot registers the package migrations, artisan commands, and the publishable
// config (for `vendor:publish`). HTTP routes are NOT registered here — the app
// calls routes.Register from its routing callback (see the package doc).
func (r *ServiceProvider) Boot(app foundation.Application) {
	cfg := app.MakeConfig()
	guards := routes.GuardOptions()

	// Goravel guard registration — the SAME in single- and multi-guard mode:
	// authkit ensures each of its guards exists in the auth config (session driver
	// over one shared orm provider), but never clobbers a guard the host already
	// defined. So a fresh app needs no config/auth.go, while an existing app's
	// hand-written guards still win. Guard resolution is lazy, so setting this at
	// boot is honoured at request time. Opt out wholesale with
	// authkit.register_guards = false to own config/auth.go yourself.
	if cfg != nil && cfg.GetBool("authkit.register_guards", true) && len(guards) > 0 {
		cfg.Add("auth.providers."+ormProviderName+".driver", "orm")
		if cfg.GetString("auth.defaults.guard") == "" {
			// The framework default guard (used by facades.Auth(ctx) with no
			// .Guard(name)) is authkit.default_guard if set, else the first declared
			// guard. authkit itself always passes an explicit guard.
			def := cfg.GetString("authkit.default_guard")
			if def == "" {
				def = guards[0].Guard
			}
			cfg.Add("auth.defaults.guard", def)
		}
		for _, o := range guards {
			if cfg.GetString("auth.guards."+o.Guard+".driver") == "" {
				cfg.Add("auth.guards."+o.Guard+".driver", "session")
				cfg.Add("auth.guards."+o.Guard+".provider", ormProviderName)
			}
		}
	}

	// Migrations — the SAME in both modes: ForTables for every guard's tables
	// (single-guard uses the default table names). Opt out with
	// authkit.register_migrations = false to register migrations.ForTables yourself.
	if schema := app.MakeSchema(); schema != nil {
		if cfg == nil || cfg.GetBool("authkit.register_migrations", true) {
			for _, o := range guards {
				schema.Register(migrations.ForTables(migrations.MigrationConfig{
					UsersTable:          o.UsersTable,
					AuditTable:          o.AuditTable,
					RememberTokensTable: o.RememberTokensTable,
					SessionsTable:       o.SessionsTable,
					APITokensTable:      o.APITokensTable,
				}))
			}
		}
	}

	// Artisan commands.
	tokenTables := make([]string, 0, len(guards))
	for _, o := range guards {
		tokenTables = append(tokenTables, o.APITokensTable)
	}
	app.Commands([]console.Command{
		commands.NewCreateUser(),
		commands.NewPruneRememberTokens(),
		commands.NewPruneAPITokens(tokenTables...),
	})

	// Publishable config — `./artisan vendor:publish --tag=authkit` writes
	// config/authkit.go (the guard + hashing tweaks are applied by setup.go on
	// package:install, not published, so they never clobber the app's files).
	app.Publishes(PackageName, map[string]string{
		"setup/config/authkit.go": app.ConfigPath("authkit.go"),
	}, "authkit")
}
