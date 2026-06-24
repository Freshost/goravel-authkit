# Installation

`goravel-authkit` is a backend Go module for [Goravel](https://www.goravel.dev)
apps (tested against Goravel **v1.17.x**, Go **1.25+**, PostgreSQL). It owns the
`users` and `audit_logs` tables (plus a guard's remember-token and session
tables) — or, in multi-guard mode, the per-guard tables you declare.

## Quick install (fresh app)

```bash
go get github.com/freshost/goravel-authkit
./artisan package:install github.com/freshost/goravel-authkit
# one-time: mount the routes in your routing callback (see below)
./artisan migrate
./artisan auth:create-user --email=admin@example.com --password=change-me
```

`package:install` registers the provider and writes `config/authkit.go`; you then
add **one line** to your routing callback to mount the routes (see
[Wire routes](#wire-routes-one-time)). The provider auto-registers a Goravel
session guard and the migrations from that config, so a fresh app needs **no
`config/auth.go`** and the package starts its own session — no global session
middleware is needed. `auth:create-user` also reads `ADMIN_EMAIL` /
`ADMIN_PASSWORD` env vars if the flags are omitted.

> **The only two things you configure** are (1) `config/authkit.go` — including
> the optional `authkit.guards` block — and (2) the one-line
> `authkitroutes.RegisterAll(facades.Route())` in the routing callback.

### What `package:install` does

It makes two small, **additive** edits (it does not overwrite your existing
config):

1. Registers `authkit.ServiceProvider` into `bootstrap/providers.go`.
2. Writes a new **`config/authkit.go`** — package settings (route prefix, rate
   limit, feature toggles, and the optional `authkit.guards` block; see
   [configuration](configuration.md)).

Everything else the package needs is auto-wired by the provider at boot — there
is no edit to `config/auth.go`. If you want bcrypt to match the rest of this
stack, set **`rounds: 12`** in your `config/hashing.go` (a fresh Goravel app
ships that file).

### What the ServiceProvider does at boot

For **every guard** (each entry under `authkit.guards`, or the single default
guard when none are declared), with no edits to `bootstrap/migrations.go` or
`config/auth.go`:

- **Session guard** — registers a Goravel `session` guard over a shared
  `authkit_orm` provider, so you don't hand-write `config/auth.go`. A guard the
  host already defined is left untouched. Opt out with
  `authkit.register_guards = false`.
- **Migrations** — registers `migrations.ForTables(...)` for that guard's tables
  via the schema facade, so `./artisan migrate` runs them. Opt out with
  `authkit.register_migrations = false`.
- **Commands** — registers `auth:create-user` and `auth:prune-remember-tokens`.
- **Publish** — exposes `config/authkit.go` for `./artisan vendor:publish --tag=authkit`.

### Wire routes (one-time)

The package is **session-cookie** auth, but it starts its own session: it mounts
Goravel's `StartSession` on each guard's `/auth` group. So you only have to mount
the routes — no global session middleware needed. One call mounts **every**
declared guard (or the single default guard):

```go
import (
	authkitroutes "github.com/freshost/goravel-authkit/routes"
)

foundation.Setup().
	WithRouting(func() {
		routes.Web()
		// Mount every authkit guard (or the single default). Each guard starts
		// the session on its own /auth group, so no global StartSession /
		// WithMiddleware is required.
		authkitroutes.RegisterAll(facades.Route())
	}).
	// ...
```

`RegisterAll` iterates `authkit.guards` (or falls back to the single
top-level config) and registers each. If you need finer control, the lower-level
entry points are still there: `Register(router, authkitroutes.Options{...})`,
`OptionsForGuard(name)` (one guard's resolved options) and `GuardOptions()` (the
slice for all guards).

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
`/auth/password`, the two-factor endpoints, the `/sessions` endpoints, and the
`/users` CRUD — under each guard's prefix. See the
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
- **No OpenAPI annotations.** As of v0.2.0 the controllers ship **no
  Swagger/`@`-annotations** (per-guard mounting can't be expressed statically), so
  `swag` will not pick up authkit's endpoints. Document them with a route-/type-driven
  generator, or pair with the hand-written React `@freshost/authkit-ui`. See the
  [API reference](api-reference.md) for the endpoint shapes.

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

Then do by hand only what `package:install` would have done: add a
`config/authkit.go` (copy from the package's `setup/config/authkit.go`) and mount
the routes from your routing callback (see [above](#wire-routes-one-time)).
Optionally set bcrypt `rounds: 12` in `config/hashing.go`. You do **not** need to
write `config/auth.go` — the provider auto-registers the session guard(s). Then
`./artisan migrate` and create the admin.

> A complete, runnable wiring of exactly this lives in the
> [`authkit-ui` demo backend](https://github.com/Freshost/authkit-ui/tree/main/demo/backend) —
> copy its `bootstrap/app.go`, `config/authkit.go` and `routes/web.go` if you
> want a reference.

The session guard and migrations are auto-registered by the provider from your
config; only the one-line `authkitroutes.RegisterAll(...)` is wired app-side (it
starts its own session). All behaviour is tuned through the `authkit.*` config.
See [configuration](configuration.md).

## Adopting into an existing app

If your app already has its own auth/users, follow the
[adoption skill](https://github.com/Freshost/goravel-authkit/blob/main/.claude/skills/adopt-goravel-authkit/SKILL.md)
— it reconciles the `admin` guard, covers the `admin_users → users` data
migration, and verification.
