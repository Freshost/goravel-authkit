# goravel-authkit demo (backend)

A minimal, runnable Goravel app that wires **goravel-authkit** with the least code
possible — the reference backend for trying the package and the backend the
[`authkit-ui` frontend demo](https://github.com/Freshost/authkit-ui/tree/main/demo)
talks to.

It consumes the package **locally** via a `replace` directive to the repo root
(`..`), so nothing needs to be published.

## Prerequisites

- Go 1.25+
- PostgreSQL on `127.0.0.1:5432` (the package migrations are Postgres-specific)

## Run (port 8090)

```bash
cp .env.example .env                 # set DB_USERNAME/DB_PASSWORD for your Postgres
createdb authkit_demo                # or: psql -c 'create database authkit_demo'
go run . artisan key:generate
go run . artisan migrate
go run . artisan auth:create-user --email=admin@demo.test --password=password123 --name=Admin
go run .                             # serves http://127.0.0.1:8090
```

Smoke test:

```bash
curl -i -c j -b j -XPOST localhost:8090/api/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"admin@demo.test","password":"password123"}'
curl -c j -b j localhost:8090/api/v1/auth/me
```

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
`/api` → `:8090`.
