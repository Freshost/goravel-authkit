package routes

import (
	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/contracts/route"

	authkitroutes "github.com/freshost/goravel-authkit/routes"

	"goravel/app/facades"
)

// Web holds the demo app's own routes plus the goravel-authkit guards.
//
// Both authkit guards (admin at /api/v1, client at /api/client/v1) are declared in
// config/authkit.go under "authkit.guards"; RegisterAll mounts them all in one call.
// authkit auto-registers their Goravel guards and migrations, so there is no
// config/auth.go and no per-instance route wiring here.
//
// Routes are mounted HERE (in the routing callback), not in the package's
// ServiceProvider, because routes a provider registers in Boot are discarded if
// Goravel rebuilds the HTTP engine (which any global WithMiddleware triggers).
func Web() {
	facades.Route().Get("/", func(ctx http.Context) http.Response {
		return ctx.Response().Success().Json(http.Json{
			"app":    "authkit-demo",
			"admin":  "/api/v1",
			"client": "/api/client/v1",
		})
	})

	authkitroutes.RegisterAll(facades.Route())

	// A host-owned route protected by the "client" guard — shows how to apply an
	// authkit guard to your own routes and read the current user. Only a logged-in
	// client (not an admin) reaches it.
	facades.Route().Prefix("/api/client/v1/portal").Middleware(authkitroutes.Protect("client")...).
		Group(func(r route.Router) {
			r.Get("/whoami", func(ctx http.Context) http.Response {
				return ctx.Response().Success().Json(http.Json{
					"userId": authkitroutes.AuthUserID(ctx).String(),
				})
			})
		})
}
