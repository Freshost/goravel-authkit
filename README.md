# goravel-authkit

[![Release](https://img.shields.io/github/v/release/Freshost/goravel-authkit?sort=semver)](https://github.com/Freshost/goravel-authkit/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/freshost/goravel-authkit.svg)](https://pkg.go.dev/github.com/freshost/goravel-authkit)
[![Go Report Card](https://goreportcard.com/badge/github.com/freshost/goravel-authkit)](https://goreportcard.com/report/github.com/freshost/goravel-authkit)
[![Built for Goravel](https://img.shields.io/badge/built%20for-Goravel-00B7EB)](https://www.goravel.dev)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
[![Changelog](https://img.shields.io/badge/changelog-keep--a--changelog-orange)](CHANGELOG.md)

Batteries-included, session-based **authentication + user management** for
[Goravel](https://www.goravel.dev) apps — now with **multi-guard**: run several
independent auth domains (e.g. an internal `admin` console and a customer `client`
portal) side-by-side in one app. Install it, declare your guards, mount one route —
and it publishes the API routes, the database migrations, the Goravel session
guards and the (optional) admin user-management endpoints for you.

Inspired by [`jeremykenedy/laravel-auth`](https://github.com/jeremykenedy/laravel-auth),
adapted to Go/Goravel idioms (static typing, code-based migrations). The
React/PatternFly frontend counterpart lives in
[`@freshost/authkit-ui`](https://github.com/freshost/authkit-ui).

> **Status:** `v0.2.0` (pre-1.0). Ships the core that real projects already use:
> login/logout/session, change-password with other-session invalidation, login
> rate-limiting, admin user-management CRUD, an audit log, **TOTP two-factor**,
> remember-me, active-session tracking, and — new in 0.2.0 — **multi-guard**.
> Later phases: self-registration, email verification, password reset by email,
> RBAC. While pre-1.0, minor versions may carry breaking changes — see the
> [CHANGELOG](CHANGELOG.md).

#### Table of contents

- [About](#about)
- [Features](#features)
- [Multi-guard](#multi-guard)
- [Installation](#installation)
- [Routes](#routes)
- [Configuration](#configuration)
- [Protect your own routes with a guard](#protect-your-own-routes-with-a-guard)
- [Programmatic API (facade)](#programmatic-api-facade)
- [Documentation](#documentation)
- [Security notes](#security-notes)
- [Opening an issue](#opening-an-issue)
- [License](#license)

## About

`goravel-authkit` is a drop-in authentication module for Goravel. Rather than
hand-rolling login, sessions, password changes, two-factor and a user-management
UI in every project, you register the provider and declare your auth **guards** in
one config block — the package wires the tables, migrations, Goravel session
guards and HTTP routes for you. A single-guard app is a one-liner; a multi-domain
app (separate clients and admins) is the same config with more than one guard.

It is **session-cookie based** (httpOnly, no tokens, no localStorage), uses bcrypt
(cost 12), and keeps everything server-side. The companion React UI
([`@freshost/authkit-ui`](https://github.com/freshost/authkit-ui)) is hand-written
against these endpoints.

## Features

| goravel-authkit features |
| --- |
| Built on [Goravel](https://www.goravel.dev) (Go) — static typing, code-based migrations, no annotations |
| **Multi-guard** — any number of independent auth domains in one app, each with its own user table, Goravel session guard, route prefix, remember cookie, rate-limit bucket and feature set |
| Session-based login / logout / current-user — httpOnly cookie, **bcrypt cost 12**, no tokens or localStorage |
| Login **rate-limiting** per IP, per guard, with session-fixation protection |
| Change password with **other-session invalidation** (`password_changed_at`) |
| **TOTP two-factor** — enroll / confirm / disable, encrypted secret, single-use recovery codes (toggleable, per guard) |
| **Remember-me** persistent login — rotating selector/validator tokens, per-guard cookie |
| **Active-session tracking** — device list + remote termination, keyed by a stable per-guard token |
| **Admin user management** CRUD behind a fail-closed role gate; keeps at least one active admin (toggleable) |
| Per-guard **audit log** table + writer |
| Account disable/lock (`disabled_at`) refuses login and live sessions |
| **Auto-wiring** — registers a Goravel session guard and the migrations for each declared guard (no `config/auth.go`); opt-out flags |
| **Protect your own routes** with any guard — `Protect` / `ProtectRole` / `AuthUserID` (the `auth:guard` equivalent) |
| **Programmatic facade** for seeders, installers, CLI and domain code |
| `auth:create-user` artisan command to bootstrap the first admin |
| Hand-written React/PatternFly companion: [`@freshost/authkit-ui`](https://github.com/freshost/authkit-ui) |

## Multi-guard

A **guard** is a self-contained auth domain: its own user table, Goravel session
guard, route prefix, remember cookie, rate-limit bucket and feature set. Declare as
many as you like under `authkit.guards` in `config/authkit.go` and they run
side-by-side — e.g. an internal `admin` console and a customer-facing `client`
portal, each with its own users:

```go
config.Add("authkit", map[string]any{
    // Root-level authkit.* settings apply to every guard; a guard can override them.
    "min_password_length":   8,
    "user_management_roles": []string{"admin"},

    "guards": map[string]any{
        "admin": map[string]any{
            "prefix":      "/api/v1",      // routes under /api/v1/auth, /api/v1/users …
            "users_table": "users",
        },
        "client": map[string]any{
            "prefix":              "/api/client/v1",
            "users_table":         "client_users", // secondary tables default to client_audit_logs, etc.
            "min_password_length": 12,             // per-guard override wins
            "features":            map[string]any{"two_factor": false},
        },
    },
})
```

Each guard's secondary tables (`<name>_audit_logs`, remember tokens, sessions),
session keys and remember cookie are namespaced, so two guards on one origin never
collide. The package auto-registers a Goravel session guard and the migrations for
every declared guard — **no `config/auth.go` needed** (opt out with
`authkit.register_guards` / `authkit.register_migrations = false`).

**Single-guard apps are unchanged:** omit `authkit.guards` and keep `authkit.guard`
/ `authkit.route_prefix` — behaviour is exactly `v0.1.0`.

## Installation

```bash
go get github.com/freshost/goravel-authkit
```

1. Run the installer — it makes three small, additive edits to your app:

   ```bash
   ./artisan package:install github.com/freshost/goravel-authkit
   ```

   1. registers `authkit.ServiceProvider` in `bootstrap/providers.go`;
   2. writes `config/authkit.go` (the package's own settings file);
   3. sets bcrypt cost 12 in your existing `config/hashing.go`.

2. Declare your guard(s) in `config/authkit.go` (see [Multi-guard](#multi-guard)
   above). A single-guard app can keep the published defaults.

3. Mount the routes with **one line** in your routing callback (`routes/web.go`) —
   it covers every declared guard:

   ```go
   import authkitroutes "github.com/freshost/goravel-authkit/routes"

   func Web() {
       authkitroutes.RegisterAll(facades.Route())
   }
   ```

4. Run the migrations and create the first admin:

   ```bash
   ./artisan migrate
   ./artisan auth:create-user --email=admin@example.com --password=change-me
   ```

That's the whole integration. You do **not** append migrations or write
`config/auth.go` by hand — the provider auto-registers the Goravel session guard
and the migrations for each guard declared in `config/authkit.go` (an existing
hand-written guard still wins). Routes are mounted in the routing callback (not in
the provider) because Goravel rebuilds the HTTP engine when global middleware is
set, which would discard routes a provider registered in `Boot`.

> **Existing auth already?** The install is additive, but if your app already has
> an auth guard, a `users` table, or its own login code, follow the bundled
> [adoption skill](.claude/skills/adopt-goravel-authkit/SKILL.md) (reconcile the
> guard, reshape your existing tables) instead of the plain install.

For local development before the module is published, add a `replace` directive
(`replace github.com/freshost/goravel-authkit => ../goravel-authkit`) and register
the provider manually (`&authkit.ServiceProvider{}` in `bootstrap/providers.go`).

## Routes

Each guard mounts the same endpoint set under its own `prefix` (e.g.
`/api/v1/auth/login` for `admin`, `/api/client/v1/auth/login` for `client`):

| Endpoint | Description |
| --- | --- |
| `POST /auth/login` | Session login (rate-limited), bcrypt verification |
| `POST /auth/logout` | Destroys the session |
| `GET  /auth/me` | Current authenticated user |
| `PUT  /auth/me` | Update own profile |
| `PUT  /auth/password` | Change password (invalidates other sessions) |
| `POST /auth/two-factor-challenge` | Complete a 2FA login |
| `POST /auth/two-factor` … | TOTP enroll / confirm / disable / recovery-codes (toggleable) |
| `GET/DELETE /auth/sessions` | List / terminate active sessions |
| `GET  /auth/logins` | Recent sign-in history |
| `GET/POST/PUT/DELETE /auth/users` | Admin user management (toggleable, role-gated) |
| `POST /auth/users/{id}/password` | Admin set-password |
| `GET  /auth/meta` | Public per-guard config (for the frontend) |

> **Note on SDKs / Swagger:** the package ships **no** Swagger/OpenAPI annotations
> (dynamic per-guard mounting can't be expressed in static annotations), so
> authkit's endpoints won't appear in a host's `swag`-generated OpenAPI. The React
> companion [`@freshost/authkit-ui`](https://github.com/freshost/authkit-ui) is
> hand-written against these endpoints.

## Configuration

Everything is tuned through `config/authkit.go` that `package:install` writes (all
keys optional — the package falls back to safe defaults).

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `authkit.guards` | map | — | Per-guard config (multi-guard). Each key is a guard name; value carries `prefix`, `users_table` and optional overrides. Omit for single-guard. |
| `authkit.guard` | string | `admin` | Single-guard: the Goravel session guard name |
| `authkit.route_prefix` | string | `/api/v1` | Single-guard: prefix for all routes |
| `authkit.min_password_length` | int | `8` | Minimum new-password length |
| `authkit.rate_limit.attempts` | int | `5` | Login attempts per window per IP |
| `authkit.rate_limit.window` | int | `60` | Rate-limit window (seconds) |
| `authkit.features.user_management` | bool | `true` | Register `/users` CRUD |
| `authkit.features.audit_log` | bool | `true` | Write audit entries |
| `authkit.features.two_factor` | bool | `true` | Register TOTP endpoints + login gate |
| `authkit.features.remember_me` | bool | `true` | Persistent "remember me" login |
| `authkit.features.sessions` | bool | `true` | Active-session tracking + endpoints |
| `authkit.two_factor.issuer` | string | `""` | Authenticator issuer (empty = app name) |
| `authkit.two_factor.recovery_codes` | int | `8` | Recovery codes per confirmation |
| `authkit.user_management_roles` | []string | `[]` | Roles allowed on `/users` (empty = any) |
| `authkit.register_guards` | bool | `true` | Auto-register a Goravel session guard per declared guard |
| `authkit.register_migrations` | bool | `true` | Auto-register the migrations for each guard's tables |

Root-level `authkit.*` settings apply to **every** guard; anything set inside an
`authkit.guards.<name>` entry overrides them for that guard. A guard's secondary
tables default from its `users_table` (e.g. `client_users` → `client_audit_logs`).
See [docs/configuration.md](docs/configuration.md) for the full reference.

## Protect your own routes with a guard

To put one of authkit's guards in front of a route your host app owns (the authkit
equivalent of Laravel's `auth:guard`), use `Protect` / `ProtectRole` for the
middleware chain and `AuthUserID` to read the current user:

```go
import authkitroutes "github.com/freshost/goravel-authkit/routes"

facades.Route().Prefix("/api/client/v1/portal").
    Middleware(authkitroutes.Protect("client")...).
    Group(func(r route.Router) {
        r.Get("/whoami", func(ctx http.Context) http.Response {
            return ctx.Response().Success().Json(http.Json{
                "userId": authkitroutes.AuthUserID(ctx).String(),
            })
        })
    })

// Or require a role: authkitroutes.ProtectRole("client", "admin")
```

## Programmatic API (facade)

Besides the HTTP endpoints, the package exposes a facade so your own Go code
(seeders, installers, custom commands, domain logic) can drive auth/users without
HTTP:

```go
import authfacades "github.com/freshost/goravel-authkit/facades"

user, err := authfacades.Authkit().CreateUser(ctx, "jane@example.com", "Jane", "secret123", "admin")
user, err := authfacades.Authkit().Authenticate(ctx, email, password)
err := authfacades.Authkit().ChangePassword(ctx, id, current, next)

// two-factor
secret, url, err := authfacades.Authkit().EnableTwoFactor(ctx, id)
codes, err := authfacades.Authkit().ConfirmTwoFactor(ctx, id, "123456")
```

For multi-table apps, build an instance bound to a specific guard's table with
`authkit.New(authkit.Config{Guard: "client", UsersTable: "client_users"})`. See
[`contracts/authkit.go`](contracts/authkit.go) for the full interface.

## Documentation

- [Installation](docs/installation.md) — full wiring (provider, config, migrations, routes, first admin).
- [Configuration](docs/configuration.md) — `authkit.*` keys, guards, per-guard overrides, feature toggles, the role gate.
- [API reference](docs/api-reference.md) — endpoints, request/response shapes, error codes, the Go API surface.
- [Security model](docs/security.md) — guarantees, operator responsibilities, multi-guard isolation, audit actions.
- [Architecture](docs/architecture.md) — layering, the canonical model, Goravel integration, repo-based user loading.

**Adopting into an existing app?** There is a bundled agent skill at
[`.claude/skills/adopt-goravel-authkit/`](.claude/skills/adopt-goravel-authkit/SKILL.md)
— copy it into your project's `.claude/skills/` and an AI agent can perform the
swap step by step.

## Security notes

Read before deploying:

- **Hashing is bcrypt cost 12.** `package:install` writes `config/hashing.go` with
  bcrypt cost 12 (what existing `$2a$12$` hashes verify against). The package hashes
  via the Goravel `Hash` facade.
- **Configure trusted proxies.** The login rate-limiter and the audit log key on
  `ctx.Request().Ip()`, which honours `X-Forwarded-For`. Behind a proxy/CDN, set
  Goravel's `http.trusted_proxies` or the limit is bypassable (and audit IPs
  spoofable) by sending a forged header.
- **No full RBAC yet.** The `/users` endpoints sit behind the session guard; gate
  them with `authkit.user_management_roles` (e.g. `[]string{"admin"}`) to add a
  `RequireRole` check. True RBAC (roles/permissions tables) is a later phase.
- **Each guard is an isolated auth domain** — separate user table, session key,
  remember cookie and rate-limit bucket. Active-session tracking is keyed by a
  stable per-guard token, so concurrent logins to several guards in one browser all
  keep working. For stronger isolation, run each portal on its own subdomain/origin.
- **Sessions** use httpOnly cookies with session-id regeneration on login
  (anti-fixation) and `password_changed_at` multi-session invalidation. Set
  `session.same_site` to `lax`/`strict` and `session.secure=true` in production.

## Opening an issue

Found a bug or have a feature request? Please
[open an issue](https://github.com/Freshost/goravel-authkit/issues) with the
goravel-authkit version, your Go and Goravel versions, and a minimal reproduction
(ideally a failing test against the bundled `demo/` app).

## License

MIT © Freshost. See [LICENSE](LICENSE).
