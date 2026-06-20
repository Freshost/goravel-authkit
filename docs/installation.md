# Installation

`goravel-auth` is a backend Go module for [Goravel](https://www.goravel.dev)
apps (tested against Goravel **v1.17.x**, Go **1.25+**, PostgreSQL). It owns the
`users` and `audit_logs` tables.

## Quick install (fresh app)

```bash
go get github.com/freshost/goravel-auth
./artisan package:install github.com/freshost/goravel-auth
./artisan migrate
./artisan auth:create-user --email=admin@example.com --password=change-me
```

That's the whole integration. `auth:create-user` also reads `ADMIN_EMAIL` /
`ADMIN_PASSWORD` env vars if the flags are omitted.

### What `package:install` does

1. Registers `auth.ServiceProvider` into your provider list (`bootstrap/providers.go`).
2. Writes three config files into your app's `config/`:
   - **`config/auth.go`** — the session `admin` guard → `users` ORM provider.
   - **`config/authkit.go`** — package settings (route prefix, rate limit,
     feature toggles; see [configuration](configuration.md)).
   - **`config/hashing.go`** — bcrypt cost 12.

### What the ServiceProvider does at boot

The provider wires everything else itself — you do **not** edit
`bootstrap/migrations.go` or any routes file:

- **Migrations** — registers `CreateUsers` + `CreateAuditLogs` via the schema
  facade, so `./artisan migrate` runs them.
- **Routes** — mounts the auth + user-management endpoints from the `authkit.*`
  config (via `app.MakeRoute()`).
- **Commands** — registers `auth:create-user`.
- **Publish** — exposes the config files for `./artisan vendor:publish --tag=authkit`.

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
require github.com/freshost/goravel-auth v0.0.0
replace github.com/freshost/goravel-auth => /absolute/path/to/goravel-auth
```

```go
// bootstrap/providers.go
import auth "github.com/freshost/goravel-auth"
// ... &auth.ServiceProvider{},
```

Then add `config/auth.go`, `config/authkit.go`, `config/hashing.go` (copy from
the package's `setup/config/`), `./artisan migrate`, and create the admin.

The package exposes **only** `auth.ServiceProvider`; everything else
(migrations, routes, controllers, services) lives under `internal/` and is not
importable. All behaviour is tuned through the `authkit.*` config — see
[configuration](configuration.md). There is no manual route/migration wiring.

## Adopting into an existing app

If your app already has auth/users, **do not** run the plain install (it would
overwrite your `config/auth.go`). Follow the
[adoption skill](../.claude/skills/adopt-goravel-auth/SKILL.md), which covers
merging the guard, the `admin_users → users` data migration, and verification.
