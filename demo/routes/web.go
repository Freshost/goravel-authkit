package routes

import (
	"context"
	"strings"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/contracts/route"

	authkit "github.com/freshost/goravel-authkit"
	authkitroutes "github.com/freshost/goravel-authkit/routes"

	"goravel/app/facades"
)

// demoImpersonationPolicy is the optional fine-grained impersonation hook. authkit's
// config gate (roles / target_guards / protected_roles) runs first; this only
// tightens it. Here it refuses any target whose email carries a "+nohook" tag.
type demoImpersonationPolicy struct{}

func (demoImpersonationPolicy) CanImpersonate(_ context.Context, _ authkit.Principal, _ string, target authkit.Principal) (bool, error) {
	return !strings.Contains(target.Email, "+nohook@"), nil
}

// Web holds the demo app's own routes plus the goravel-authkit guards.
//
// Both authkit guards (admin at /api/v1, client at /api/client/v1) are declared in
// config/authkit.go under "authkit.guards"; RegisterAll mounts them all in one call.
// authkit auto-registers their Goravel guards and migrations, so there is no
// config/auth.go and no per-instance route wiring here.
//
// Routes are mounted HERE as Authkit's explicit integration contract. This keeps
// dynamic guard registration visible in the host's routing callback and avoids
// duplicate provider-side route registration.
func Web() {
	facades.Route().Get("/", func(ctx http.Context) http.Response {
		return ctx.Response().Success().Json(http.Json{
			"app":    "authkit-demo",
			"admin":  "/api/v1",
			"client": "/api/client/v1",
		})
	})

	// Optional fine-grained impersonation rule (config gate still applies first).
	authkit.RegisterImpersonationPolicy(demoImpersonationPolicy{})

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

	facades.Route().Prefix("/api/client/v1/token").Middleware(authkitroutes.ProtectToken("client", "profile:read")...).
		Group(func(r route.Router) {
			r.Get("/whoami", authIdentity)
		})
	facades.Route().Prefix("/api/client/v1/token-write").Middleware(authkitroutes.ProtectToken("client", "profile:write")...).
		Group(func(r route.Router) {
			r.Get("/whoami", authIdentity)
		})
	facades.Route().Prefix("/api/client/v1/either").Middleware(authkitroutes.ProtectAny("client", "profile:read")...).
		Group(func(r route.Router) {
			r.Get("/whoami", authIdentity)
		})
}

func authIdentity(ctx http.Context) http.Response {
	return ctx.Response().Success().Json(http.Json{
		"userId":     authkitroutes.AuthUserID(ctx).String(),
		"authMethod": authkitroutes.AuthMethod(ctx),
		"tokenId":    authkitroutes.APITokenID(ctx).String(),
		"canRead":    authkitroutes.TokenCan(ctx, "profile:read"),
	})
}
