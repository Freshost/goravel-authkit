# Installation

`goravel-authkit` is a backend Go module for [Goravel](https://www.goravel.dev)
apps (tested against Goravel **v1.17.x**, Go **1.25+**, PostgreSQL). It owns the
`users` and `audit_logs` tables.

## Quick install (fresh app)

```bash
go get github.com/freshost/goravel-authkit
./artisan package:install github.com/freshost/goravel-authkit
# one-time: wire session middleware + routes in bootstrap/app.go (see below)
./artisan migrate
./artisan auth:create-user --email=admin@example.com --password=change-me
```

`package:install` registers the provider and writes the config; you then add two
lines to `bootstrap/app.go` to enable sessions and mount the routes (see
[Wire sessions + routes](#wire-sessions--routes-one-time)). `auth:create-user`
also reads `ADMIN_EMAIL` / `ADMIN_PASSWORD` env vars if the flags are omitted.

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

### Wire sessions + routes (one-time)

The package is **session-cookie** auth, so two things must be wired in
`bootstrap/app.go` — the provider cannot do them itself, because Goravel rebuilds
the HTTP engine when global middleware is set (which happens *after* providers
boot), discarding any routes a provider registers in its `Boot`. Add:

```go
import (
	"github.com/goravel/framework/contracts/foundation/configuration"
	sessionmiddleware "github.com/goravel/framework/session/middleware"
	authkitroutes "github.com/freshost/goravel-authkit/routes"
)

foundation.Setup().
	// 1) session middleware must run globally
	WithMiddleware(func(h configuration.Middleware) {
		h.Append(sessionmiddleware.StartSession())
	}).
	WithRouting(func() {
		routes.Web()
		// 2) mount authkit routes here (this callback runs after the engine
		//    rebuild, so the routes survive)
		authkitroutes.Register(facades.Route(), authkitroutes.OptionsFromConfig())
	}).
	// ...
```

After that you have `POST /api/v1/auth/login`, `/auth/me`, `/auth/logout`,
`/auth/password`, the two-factor endpoints, and the `/users` CRUD. See the
[API reference](api-reference.md).

## Production checklist

- Serve over **HTTPS**; set `session.secure=true` and a `session.same_site`.
- If behind a proxy/CDN, set `http.trusted_proxies` (rate-limit + audit IP
  depend on it — see [security](security.md)).
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
`setup/config/authkit.go`). Wire sessions + routes in `bootstrap/app.go` (see
[above](#wire-sessions--routes-one-time)). Then `./artisan migrate` and create
the admin.

> A complete, runnable wiring of exactly this lives in the
> [`authkit-ui` demo backend](https://github.com/Freshost/authkit-ui/tree/main/demo/backend) —
> copy its `bootstrap/app.go`, `config/auth.go`, `config/authkit.go` and
> `routes/web.go` if you want a reference.

Migrations are registered by the provider; only the session middleware and the
one-line `authkitroutes.Register(...)` are wired app-side. All behaviour is tuned
through the `authkit.*` config. See [configuration](configuration.md).

## Adopting into an existing app

If your app already has its own auth/users, follow the
[adoption skill](https://github.com/Freshost/goravel-authkit/blob/main/.claude/skills/adopt-goravel-authkit/SKILL.md)
— it reconciles the `admin` guard, covers the `admin_users → users` data
migration, and verification.
