# goravel-authkit demo (backend)

A minimal, runnable Goravel app that wires **goravel-authkit** with the least code
possible — the reference backend for trying the package and the backend the
[`authkit-ui` frontend demo](https://github.com/Freshost/authkit-ui/tree/main/demo)
talks to.

It consumes the package **locally** via a `replace` directive to the repo root
(`..`), so nothing needs to be published.

## Prerequisites

- Go 1.25+
- [air](https://github.com/air-verse/air) for hot reload (`go install github.com/air-verse/air@latest`)
- PostgreSQL on `127.0.0.1:5432` (the default). The package migrations are
  driver-agnostic — `DB_CONNECTION=sqlite DB_DATABASE=/tmp/x.db` also works.

## Run (port 8099)

Everything is driven through the `Makefile` (`make help` lists targets).

```bash
cp .env.example .env            # set DB_USERNAME/DB_PASSWORD for your Postgres
go run . artisan key:generate   # one-time, if APP_KEY is empty
make setup                      # one-time: createdb + migrate + seed admin@demo.test
make dev                        # hot reload (air) → http://127.0.0.1:8099
```

`make run` is the one-shot `go run .` without reload. Smoke-test the running
backend with `make smoke` (login + `/me` as the seeded admin).

## The whole authkit integration

Exactly four touch-points — everything else is the stock Goravel skeleton:

| file | what |
| --- | --- |
| `bootstrap/providers.go` | registers `&authkit.ServiceProvider{}` (migrations + `auth:create-user`) |
| `bootstrap/app.go` | global `StartSession()` middleware (session-cookie auth) |
| `routes/web.go` | `authkitroutes.Register(facades.Route(), authkitroutes.OptionsFromConfig())` |
| `config/auth.go` · `config/authkit.go` | a session `admin` guard + the package config |

Routes are registered in the routing callback (not in the provider) because
Goravel rebuilds the HTTP engine when global middleware is set — see the package
[installation docs](../docs/installation.md).

## Frontend

The React UI that drives this backend lives in the **authkit-ui** repo under
`demo/`. Start this backend first, then run that frontend — it proxies
`/api` → `:8099`.
