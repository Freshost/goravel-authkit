package bootstrap

import (
	contractsfoundation "github.com/goravel/framework/contracts/foundation"
	"github.com/goravel/framework/foundation"

	"goravel/config"
	"goravel/routes"
)

func Boot() contractsfoundation.Application {
	// No global StartSession / WithMiddleware: goravel-authkit mounts
	// StartSession on its own /auth group, so the package is self-contained.
	// Skipping global middleware also avoids the HTTP engine rebuild it triggers,
	// which would drop routes a provider registers in Boot.
	return foundation.Setup().
		WithMigrations(Migrations).
		WithRouting(func() {
			routes.Web()
			routes.Grpc()
		}).
		WithProviders(Providers).
		WithConfig(config.Boot).
		Create()
}
