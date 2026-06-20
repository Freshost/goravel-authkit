# Installation

`goravel-auth` is a backend Go module for [Goravel](https://www.goravel.dev)
apps (tested against Goravel **v1.17.x**, Go **1.25+**, PostgreSQL). It owns the
`users` and `audit_logs` tables, so adopt it on a fresh schema or migrate your
existing one (see [Adoption](#adopting-into-an-existing-app)).

## 1. Add the dependency

Once published:

```bash
go get github.com/freshost/goravel-auth
```

During local development (before the repo is public), use a `replace` directive
in your app's `go.mod` pointing at a local checkout:

```
require github.com/freshost/goravel-auth v0.0.0
replace github.com/freshost/goravel-auth => ../goravel-auth
```

then `go mod tidy`.

## 2. Register the service provider

Automatic (writes the provider into your provider list and runs publishing):

```bash
./artisan package:install github.com/freshost/goravel-auth
```

Or manually add it to `bootstrap/providers.go` (bootstrap setup) or
`config/app.go` (classic setup):

```go
import auth "github.com/freshost/goravel-auth"

// providers list
&auth.ServiceProvider{},
```

The provider registers the `auth:create-user` artisan command.

## 3. Required Goravel config

`goravel-auth` relies on three standard Goravel config files. Make sure your app
has them:

- **`config/hashing.go`** — **bcrypt, cost 12** (the package hashes via the Hash
  facade; without this, login and password changes cannot hash/verify, and it
  must be cost 12 to stay compatible with existing `$2a$12$` hashes).
- **`config/auth.go`** — a **session** guard named `admin` (or your chosen guard
  name; see [configuration](configuration.md)). Example:
  ```go
  config.Add("auth", map[string]any{
      "defaults": map[string]any{"guard": "admin"},
      "guards": map[string]any{
          "admin": map[string]any{"driver": "session", "provider": "users"},
      },
      "providers": map[string]any{
          "users": map[string]any{"driver": "orm"},
      },
  })
  ```
- **`config/session.go`** — httpOnly cookie; set `secure=true` and a
  `same_site` of `lax`/`strict` in production.

If you run behind a proxy/CDN, also set `http.trusted_proxies` (see
[security](security.md)).

## 4. Register the migrations

Append the package migrations to your registry in `bootstrap/migrations.go`:

```go
import (
    "github.com/goravel/framework/contracts/database/schema"
    authmigrations "github.com/freshost/goravel-auth/migrations"
)

func Migrations() []schema.Migration {
    return append(authmigrations.Migrations(),
        // ...your app migrations
    )
}
```

## 5. Register the routes

Call `routes.Register` from your own routes file (this keeps the package
controllers in `main.go`'s import graph so `swag` scans their annotations):

```go
import authroutes "github.com/freshost/goravel-auth/routes"

// In routes/api.go (or wherever you wire routes):
authroutes.Register(facades.Route(), authroutes.OptionsFromConfig())
```

`OptionsFromConfig()` reads the `authkit.*` config keys; or build
`authroutes.Options{...}` explicitly. See [configuration](configuration.md).

## 6. Migrate and create the first admin

```bash
./artisan migrate
./artisan auth:create-user --email=admin@example.com --password=change-me-please
# or via env: ADMIN_EMAIL / ADMIN_PASSWORD
```

## 7. Regenerate the SDK (if you use the hey-api/OpenAPI loop)

The controllers carry Swagger annotations (`@ID` = camelCase = generated TS SDK
function name). Run your `make swagger` / `make generate-api` so the frontend
gets `login`, `getMe`, `changePassword`, `listUsers`, etc. Ensure your swag
invocation parses dependencies (e.g. `swag init --parseDependency
--parseInternal`) so the package's annotations are picked up.

## Adopting into an existing app

If your app already has an auth/users implementation, follow the
[adoption skill](../.claude/skills/adopt-goravel-auth/SKILL.md), which covers
swapping the old code, the `admin_users → users` data migration, and end-to-end
verification.
