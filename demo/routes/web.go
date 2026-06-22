package routes

import (
	"github.com/goravel/framework/contracts/http"

	authkitroutes "github.com/freshost/goravel-authkit/routes"

	"goravel/app/facades"
)

// Web holds the demo app's own routes plus the goravel-authkit registration.
//
// authkit routes are mounted HERE (in the routing callback), not in the
// package's ServiceProvider, because Goravel rebuilds the HTTP engine when
// global middleware is set — which happens after providers boot — so routes a
// provider registers in Boot are discarded. This callback runs after that
// rebuild, so the routes survive.
func Web() {
	facades.Route().Get("/", func(ctx http.Context) http.Response {
		return ctx.Response().Success().Json(http.Json{
			"app":  "authkit-demo",
			"auth": "/api/v1",
		})
	})

	// All auth / 2FA / user-management endpoints under /api/v1.
	authkitroutes.Register(facades.Route(), authkitroutes.OptionsFromConfig())
}
