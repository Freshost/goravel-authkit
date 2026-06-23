# Installation

`goravel-authkit` is a backend Go module for [Goravel](https://www.goravel.dev)
apps (tested against Goravel **v1.17.x**, Go **1.25+**, PostgreSQL). It owns the
`users` and `audit_logs` tables.

## Quick install (fresh app)

```bash
go get github.com/freshost/goravel-authkit
./artisan package:install github.com/freshost/goravel-authkit
# one-time: mount the routes in bootstrap/app.go (see below)
./artisan migrate
./artisan auth:create-user --email=admin@example.com --password=change-me
```

`package:install` registers the provider and writes the config; you then add one
line to `bootstrap/app.go` to mount the routes (see
[Wire routes](#wire-routes-one-time)) — the package starts its own session, so no
global session middleware is needed. `auth:create-user` also reads `ADMIN_EMAIL`
/ `ADMIN_PASSWORD` env vars if the flags are omitted.

### What `package:install` does

It makes four small, **additive** edits (it does not overwrite your existing
guards or hashing settings):

1. Registers `authkit.ServiceProvider` into `bootstrap/providers.go`.
2. Writes a new **`config/authkit.go`** — package settings (route prefix, rate
   limit, feature toggles; see [configuration](configuration.md)).
3. Adds a session **`admin` guard** + a **`users` orm provider** into your
   existing `config/auth.go` (via `modify.AddConfig`, leaving other guards alone).
4. Sets **bcrypt `rounds: 12`** in your existing `config/hashing.go`.

> Both `config/auth.go` and `config/hashing.go` ship in a fresh Goravel app, so
> the install just edits them in place. If they are missing, copy the guard /
> bcrypt-12 settings from this README by hand.

### What the ServiceProvider does at boot

The provider registers, with no edits to `bootstrap/migrations.go`:

- **Migrations** — registers `CreateUsers` + `CreateAuditLogs` via the schema
  facade, so `./artisan migrate` runs them.
- **Commands** — registers `auth:create-user`.
- **Publish** — exposes `config/authkit.go` for `./artisan vendor:publish --tag=authkit`.

### Wire routes (one-time)

The package is **session-cookie** auth, but it starts its own session: `Register`
mounts Goravel's `StartSession` on its `/auth` group. So you only have to mount
the routes — no global session middleware needed:

```go
import (
	authkitroutes "github.com/freshost/goravel-authkit/routes"
)

foundation.Setup().
	WithRouting(func() {
		routes.Web()
		// Mount authkit routes. Register starts the session on its own /auth
		// group, so no global StartSession / WithMiddleware is required.
		authkitroutes.Register(facades.Route(), authkitroutes.OptionsFromConfig())
	}).
	// ...
```

Registering from the routing callback (rather than the provider's `Boot`) is the
robust pattern: any global `WithMiddleware` an app adds rebuilds the HTTP engine
*after* providers boot, discarding routes a provider registered in `Boot`. The
routing callback runs after that rebuild, so the routes survive.

> **Sessions on your own routes.** If your app has its *own* (non-authkit)
> session-backed routes, run `StartSession` per-group on those routes (or set it
> globally with `WithMiddleware`). A global `StartSession` is also harmless to
> the package — `StartSession` is idempotent, so the package's group-level start
> is simply skipped when a session already exists. Prefer per-group over global
> to avoid the engine rebuild and to keep sessions off stateless endpoints
> (bearer/machine APIs, health checks).

After that you have `POST /api/v1/auth/login`, `/auth/me`, `/auth/logout`,
`/auth/password`, the two-factor endpoints, and the `/users` CRUD. See the
[API reference](api-reference.md).

## Production checklist

- Serve over **HTTPS**; set `session.secure=true` and a `session.same_site`.
- **Set `http.trusted_proxies` whenever login rate-limiting or audit logging is
  enabled** (both are on by default). Without it, `X-Forwarded-For` is
  attacker-controlled: the rate limit can be bypassed and audit IPs forged. If
  you terminate TLS at a proxy/CDN this is mandatory — see [security](security.md).
- Keep `/users` admin-gated: `authkit.user_management_roles` defaults to
  `["admin"]` (fail-closed). Only widen it if you intend non-admins to manage
  users. The bootstrap `auth:create-user` creates an `admin`.
- Regenerate your SDK if you use the hey-api/OpenAPI loop (`make swagger` +
  `make generate-api`); run swag with `--parseDependency --parseInternal` so the
  package's annotations are scanned.

## Local development (repo not yet public)

Add a `replace` directive and register the provider manually:

```
// go.mod
require github.com/freshost/goravel-authkit v0.0.0
replace github.com/freshost/goravel-authkit => /absolute/path/to/goravel-authkit
```

```go
// bootstrap/providers.go
import authkit "github.com/freshost/goravel-authkit"
// ... &authkit.ServiceProvider{},
```

Then do by hand what `package:install` would have done: add an `admin` session
guard → `users` orm provider to `config/auth.go`, set bcrypt `rounds: 12` in
`config/hashing.go`, and add a `config/authkit.go` (copy from the package's
`setup/config/authkit.go`). Mount the routes in `bootstrap/app.go` (see
[above](#wire-routes-one-time)). Then `./artisan migrate` and create the admin.

> A complete, runnable wiring of exactly this lives in the
> [`authkit-ui` demo backend](https://github.com/Freshost/authkit-ui/tree/main/demo/backend) —
> copy its `bootstrap/app.go`, `config/auth.go`, `config/authkit.go` and
> `routes/web.go` if you want a reference.

Migrations are registered by the provider; only the one-line
`authkitroutes.Register(...)` is wired app-side (it starts its own session). All
behaviour is tuned through the `authkit.*` config. See
[configuration](configuration.md).

## Adopting into an existing app

If your app already has its own auth/users, follow the
[adoption skill](https://github.com/Freshost/goravel-authkit/blob/main/.claude/skills/adopt-goravel-authkit/SKILL.md)
— it reconciles the `admin` guard, covers the `admin_users → users` data
migration, and verification.
