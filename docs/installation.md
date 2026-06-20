# Installation

`goravel-authkit` is a backend Go module for [Goravel](https://www.goravel.dev)
apps (tested against Goravel **v1.17.x**, Go **1.25+**, PostgreSQL). It owns the
`users` and `audit_logs` tables.

## Quick install (fresh app)

```bash
go get github.com/freshost/goravel-authkit
./artisan package:install github.com/freshost/goravel-authkit
./artisan migrate
./artisan auth:create-user --email=admin@example.com --password=change-me
```

That's the whole integration. `auth:create-user` also reads `ADMIN_EMAIL` /
`ADMIN_PASSWORD` env vars if the flags are omitted.

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

The provider wires everything else itself — you do **not** edit
`bootstrap/migrations.go` or any routes file:

- **Migrations** — registers `CreateUsers` + `CreateAuditLogs` via the schema
  facade, so `./artisan migrate` runs them.
- **Routes** — mounts the auth + user-management endpoints from the `authkit.*`
  config (via `app.MakeRoute()`).
- **Commands** — registers `auth:create-user`.
- **Publish** — exposes `config/authkit.go` for `./artisan vendor:publish --tag=authkit`.

After install you have `POST /api/v1/auth/login`, `/auth/me`, `/auth/logout`,
`/auth/password`, and the `/users` CRUD. See the [API reference](api-reference.md).

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
`setup/config/authkit.go`). Then `./artisan migrate` and create the admin.

You only ever register `authkit.ServiceProvider` — the provider wires the
subpackages (`models`, `services`, `routes`, `migrations`, …) itself. All
behaviour is tuned through the `authkit.*` config; there is no manual
route/migration wiring. See [configuration](configuration.md).

## Adopting into an existing app

If your app already has its own auth/users, follow the
[adoption skill](../.claude/skills/adopt-goravel-authkit/SKILL.md) — it reconciles
the `admin` guard, covers the `admin_users → users` data migration, and
verification.
