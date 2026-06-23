package routes

import (
	"github.com/goravel/framework/contracts/http"

	authkitroutes "github.com/freshost/goravel-authkit/routes"

	"goravel/app/facades"
)

// Web holds the demo app's own routes plus the goravel-authkit registration.
//
// authkit routes are mounted HERE (in the routing callback), not in the
// package's ServiceProvider, because routes a provider registers in Boot are
// discarded if Goravel rebuilds the HTTP engine (which any global WithMiddleware
// triggers). The demo no longer sets global middleware — the package starts its
// own session on the /auth group — but registering from the routing callback
// stays the robust pattern regardless of what middleware the app adds later.
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
