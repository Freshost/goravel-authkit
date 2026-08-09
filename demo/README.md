# goravel-authkit demo (backend)

A minimal, runnable Goravel app that wires **goravel-authkit** with the least code
possible — the reference backend for trying the package and the backend the
[`authkit-ui` frontend demo](https://github.com/Freshost/authkit-ui/tree/main/demo)
talks to.

It runs **two independent guards** to demonstrate multi-guard:

- **`admin`** at `/api/v1` — the default `users` table, all features on.
- **`client`** at `/api/client/v1` — a separate `client_users` table, longer
  password policy, two-factor off.

Both are declared in `config/authkit.go` and mounted with a single
`RegisterAll` call. It consumes the package **locally** via a `replace` directive
to the repo root (`..`), so nothing needs to be published.

## Prerequisites

- Go 1.25+
- [air](https://github.com/air-verse/air) for hot reload (`go install github.com/air-verse/air@latest`)
- PostgreSQL on `127.0.0.1:5432` (the default). The package migrations are
  driver-agnostic — `DB_CONNECTION=sqlite` also works; use an **absolute**
  `DB_DATABASE` path (e.g. `DB_DATABASE=/tmp/authkit-demo.db`).

## Run (port 8099)

Everything is driven through the `Makefile` (`make help` lists targets).

```bash
cp .env.example .env            # set DB_USERNAME/DB_PASSWORD for your Postgres
go run . artisan key:generate   # one-time, if APP_KEY is empty
make setup                      # one-time: createdb + migrate + seed admin@demo.test
make dev                        # hot reload (air) → http://127.0.0.1:8099
```

`make setup` chains `make db`, `make migrate` and the admin seed; run
`make migrate` on its own to apply migrations for both guards (each guard's
tables are migrated automatically). `make run` is the one-shot `go run .` without
reload, and `make smoke` smoke-tests the running backend (login + `/me` as the
seeded admin).

### Tests

`make test` runs the Go suite against a **real** database (no fakes):

```bash
make test                       # AUTHKIT_RATE_LIMIT_ATTEMPTS=100000 go test ./...
```

It hits the configured Postgres by default; for a zero-setup run point it at
SQLite with an absolute path:

```bash
DB_CONNECTION=sqlite DB_DATABASE=/tmp/authkit-demo.db make test
```

The high `AUTHKIT_RATE_LIMIT_ATTEMPTS` keeps the many logins in the feature suite
from tripping the per-IP login limiter.

## The whole authkit integration

Three touch-points — everything else is the stock Goravel skeleton. Note there
is **no `config/auth.go`**: authkit auto-registers a Goravel session guard and
the migrations for every guard declared in `config/authkit.go`.

| file | what |
| --- | --- |
| `bootstrap/providers.go` | registers `&authkit.ServiceProvider{}` (auto-registers guards + migrations + `auth:create-user`) |
| `bootstrap/app.go` | global `StartSession()` middleware (session-cookie auth) |
| `config/authkit.go` | declares both guards (`admin`, `client`) under `authkit.guards` |
| `routes/web.go` | `authkitroutes.RegisterAll(facades.Route())` — mounts both guards in one line |

`routes/web.go` also shows **protecting a host-owned route with a guard**: a
`/api/client/v1/portal/whoami` endpoint behind `authkitroutes.Protect("client")`,
reading the current user with `authkitroutes.AuthUserID(ctx)` — so only a logged-in
client (not an admin) can reach it. Use `ProtectRole("client", "admin")` to also
require a role.

Routes are registered explicitly in the routing callback (not in the provider),
which keeps dynamic guard wiring visible and prevents duplicate registration. See
the package [installation docs](../docs/installation.md).

## Frontend

The React UI that drives this backend lives in the **authkit-ui** repo under
`demo/`. Start this backend first, then run that frontend — it proxies
`/api` → `:8099`.
