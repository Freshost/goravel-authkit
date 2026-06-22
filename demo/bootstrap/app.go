package bootstrap

import (
	contractsfoundation "github.com/goravel/framework/contracts/foundation"
	"github.com/goravel/framework/contracts/foundation/configuration"
	"github.com/goravel/framework/foundation"
	sessionmiddleware "github.com/goravel/framework/session/middleware"

	"goravel/config"
	"goravel/routes"
)

func Boot() contractsfoundation.Application {
	return foundation.Setup().
		// goravel-authkit is session-cookie auth — StartSession must run globally
		// so the package guard and middleware can read & write the session.
		WithMiddleware(func(handler configuration.Middleware) {
			handler.Append(
				sessionmiddleware.StartSession(),
			)
		}).
		WithMigrations(Migrations).
		WithRouting(func() {
			routes.Web()
			routes.Grpc()
		}).
		WithProviders(Providers).
		WithConfig(config.Boot).
		Create()
}
