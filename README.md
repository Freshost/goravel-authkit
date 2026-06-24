# goravel-authkit

Batteries-included, session-based **authentication + user management** for
[Goravel](https://www.goravel.dev) apps. Install it, register the provider,
configure it — and it publishes the API routes, database migrations, the `User`
model, and (optionally) the admin user-management endpoints for you.

Inspired by [`jeremykenedy/laravel-auth`](https://github.com/jeremykenedy/laravel-auth),
adapted to Go/Goravel idioms (static typing, code-based migrations). The
React/PatternFly frontend counterpart lives in
[`@freshost/authkit-ui`](https://github.com/freshost/authkit-ui).

> **Status:** v0.2.0 (pre-1.0). Ships the core that real projects already use:
> login/logout/session, change-password with other-session invalidation, login
> rate-limiting, admin user-management CRUD, an audit log, **TOTP two-factor**,
> and — new in 0.2.0 — **multi-guard** (several independent auth domains in one
> app). Later phases: self-registration, email verification, password reset by
> email, RBAC. While pre-1.0, minor versions may carry breaking changes — see the
> [CHANGELOG](CHANGELOG.md).

## Multi-guard (new in 0.2.0)

A **guard** is a self-contained auth domain: its own user table, Goravel session
guard, route prefix, remember cookie, rate-limit bucket and feature set. Declare
as many as you like under `authkit.guards` in `config/authkit.go` and they run
side-by-side in one app — e.g. an internal `admin` console and a customer-facing
`client` portal, each with its own users:

```go
config.Add("authkit", map[string]any{
    // Root-level authkit.* settings apply to every guard; a guard can override them.
    "min_password_length":   8,
    "user_management_roles": []string{"admin"},

    "guards": map[string]any{
        "admin": map[string]any{
            "prefix":      "/api/v1",     // routes under /api/v1/auth, /api/v1/users …
            "users_table": "users",
        },
        "client": map[string]any{
            "prefix":              "/api/client/v1",
            "users_table":         "client_users",   // secondary tables default to client_audit_logs, etc.
            "min_password_length": 12,               // per-guard override wins
            "features":            map[string]any{"two_factor": false},
        },
    },
})
```

Each guard's secondary tables (`<name>_audit_logs`, remember tokens, sessions),
session keys and remember cookie are namespaced, so two guards on one origin
never collide. The package auto-registers a Goravel session guard and the
migrations for every declared guard — no `config/auth.go` needed (opt out with
`authkit.register_guards` / `authkit.register_migrations = false`).

**Single-guard apps are unchanged:** omit `authkit.guards` and keep
`authkit.guard` / `authkit.route_prefix` — behaviour is exactly v0.1.0.

## What you get

| Endpoint | Description |
| --- | --- |
| `POST /auth/login` | Session login (rate-limited), bcrypt verification |
| `POST /auth/logout` | Destroys the session |
| `GET  /auth/me` | Current authenticated user |
| `PUT  /auth/password` | Change password (invalidates other sessions) |
| `POST /auth/two-factor` … | TOTP enroll / confirm / disable / recovery-codes (toggleable) |
| `POST /auth/two-factor-challenge` | Complete a 2FA login |
| `GET/POST/PUT/DELETE /users` | Admin user management (toggleable) |
| `POST /users/{id}/password` | Admin set-password |

Endpoints are mounted per guard under its `prefix` (e.g. `/api/v1/auth/login`,
`/api/client/v1/auth/login`). Plus: session-fixation protection,
`password_changed_at` multi-session invalidation, **TOTP two-factor** (encrypted
secret + single-use recovery codes), a per-guard audit-log table + writer, and an
`auth:create-user` artisan command for bootstrapping the first admin.

> **Note on SDKs/Swagger:** the package ships **no** Swagger/OpenAPI annotations
> (dynamic per-guard mounting can't be expressed in static annotations), so
> authkit's endpoints won't appear in a host's `swag`-generated OpenAPI. The
> React companion [`@freshost/authkit-ui`](https://github.com/freshost/authkit-ui)
> is hand-written against these endpoints.

## Documentation

- [Installation](docs/installation.md) — full wiring (provider, config,
  migrations, routes, first admin).
- [Configuration](docs/configuration.md) — `authkit.*` keys, feature toggles,
  the role gate.
- [API reference](docs/api-reference.md) — endpoints, request/response shapes,
  error codes, operation ids.
- [Security model](docs/security.md) — guarantees, operator responsibilities,
  v1 limitations, audit actions.
- [Architecture](docs/architecture.md) — layering, the canonical model, Goravel
  integration, the SDK contract loop.

**Adopting into an existing app?** There is a bundled agent skill at
[`.claude/skills/adopt-goravel-authkit/`](.claude/skills/adopt-goravel-authkit/SKILL.md)
— copy it into your project's `.claude/skills/` and an AI agent can perform the
swap (including the `admin_users → users` data migration) step by step.

## Install

Register the provider, then mount the routes with one line. The provider
auto-registers the Goravel guard(s), migrations and artisan commands from your
config; you add a single `RegisterAll` call in the routing callback.

```bash
go get github.com/freshost/goravel-authkit
./artisan package:install github.com/freshost/goravel-authkit
./artisan migrate
./artisan auth:create-user --email=admin@example.com --password=change-me
```

`package:install` makes three small, additive edits to your app:

1. registers `authkit.ServiceProvider` in `bootstrap/providers.go`;
2. writes `config/authkit.go` (the package's own settings file);
3. sets bcrypt cost 12 in your existing `config/hashing.go`.

Then mount the routes in your routing callback (`routes/web.go`) — one line,
which covers every declared guard:

```go
import authkitroutes "github.com/freshost/goravel-authkit/routes"

func Web() {
    authkitroutes.RegisterAll(facades.Route())
}
```

Routes are mounted here (not in the provider) because Goravel rebuilds the HTTP
engine when global middleware is set, which would discard routes a provider
registered in `Boot`. You don't append migrations or write `config/auth.go` by
hand — the provider auto-registers the Goravel session guard and migrations for
each guard declared in `config/authkit.go` (opt out with
`authkit.register_guards` / `authkit.register_migrations = false`; an existing
hand-written guard still wins).

> **Existing auth already?** The install is additive, but if your app already has
> an `admin` guard, a `users` table, or its own login code, follow the
> [adoption skill](.claude/skills/adopt-goravel-authkit/SKILL.md) (reconcile the
> guard, migrate `admin_users → users`) instead of the plain install.

For local development before the repo is public, add a `replace` directive
(`replace github.com/freshost/goravel-authkit => ../goravel-authkit`) and register the
provider manually (`&authkit.ServiceProvider{}` in `bootstrap/providers.go`).

## Configuration

Everything is tuned through the `config/authkit.go` file that `package:install`
writes (all keys optional — the package falls back to safe defaults). The
you consume the package only by registering the provider — there is no Go wiring
to do.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `authkit.route_prefix` | string | `/api/v1` | Prefix for all routes |
| `authkit.guard` | string | `admin` | Goravel session guard name |
| `authkit.min_password_length` | int | `8` | Minimum new-password length |
| `authkit.rate_limit.attempts` | int | `5` | Login attempts per window per IP |
| `authkit.rate_limit.window` | int | `60` | Rate-limit window (seconds) |
| `authkit.features.user_management` | bool | `true` | Register `/users` CRUD |
| `authkit.features.audit_log` | bool | `true` | Write audit entries |
| `authkit.features.two_factor` | bool | `true` | Register TOTP two-factor endpoints + login gate |
| `authkit.two_factor.issuer` | string | `""` | Authenticator issuer (empty = app name) |
| `authkit.two_factor.recovery_codes` | int | `8` | Recovery codes per confirmation |
| `authkit.user_management_roles` | []string | `[]` | Roles allowed on `/users` (empty = any) |
| `authkit.guards` | map | — | Per-guard config (multi-guard). Each key is a guard name; value carries `prefix`, `users_table` and optional overrides. Omit for single-guard. |
| `authkit.register_guards` | bool | `true` | Auto-register a Goravel session guard per declared guard |
| `authkit.register_migrations` | bool | `true` | Auto-register the migrations for each guard's tables |

Root-level `authkit.*` settings apply to **every** guard; anything set inside a
`authkit.guards.<name>` entry overrides them for that guard. A guard's secondary
tables default from its `users_table` (e.g. `client_users` →
`client_audit_logs`). See [docs/configuration.md](docs/configuration.md) for
details.

### Protect your own routes with a guard

To put one of authkit's guards in front of a route your host app owns (the
authkit equivalent of Laravel's `auth:guard`), use `Protect` / `ProtectRole` for
the middleware chain and `AuthUserID` to read the current user:

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
(seeders, installers, custom commands, domain logic) can drive auth/users
without HTTP:

```go
import authfacades "github.com/freshost/goravel-authkit/facades"

user, err := authfacades.Authkit().CreateUser(ctx, "jane@example.com", "Jane", "secret123", "admin")
user, err := authfacades.Authkit().Authenticate(ctx, email, password)
err := authfacades.Authkit().ChangePassword(ctx, id, current, next)

// two-factor
secret, url, err := authfacades.Authkit().EnableTwoFactor(ctx, id)
codes, err := authfacades.Authkit().ConfirmTwoFactor(ctx, id, "123456")
```

See [`contracts/authkit.go`](contracts/authkit.go) for the full interface.

## Security notes (read before deploying)

- **Hashing is bcrypt cost 12.** `package:install` writes `config/hashing.go`
  with bcrypt cost 12 (what existing `$2a$12$` hashes verify against). Keep it
  that way — the package hashes via the Goravel `Hash` facade.
- **Configure trusted proxies.** The login rate-limiter and the audit log key on
  `ctx.Request().Ip()`, which honours `X-Forwarded-For`. Behind a proxy/CDN, set
  Goravel's `http.trusted_proxies` or the limit is bypassable (and audit IPs are
  spoofable) by sending a forged header.
- **No full RBAC yet.** The `/users` management endpoints sit behind the session
  guard only — every authenticated user can manage users. Once your app assigns
  roles, gate them with `authkit.user_management_roles` (e.g.
  `[]string{"admin"}`), which adds a `RequireRole` check. True RBAC
  (roles/permissions tables) is a later phase.
- **Each guard is an isolated auth domain** — separate user table, session key,
  remember cookie and rate-limit bucket. Active-session tracking is keyed by a
  stable per-guard token, so concurrent logins to several guards in one browser all
  keep working. For stronger isolation, run each portal on its own subdomain/origin.
- **Sessions** use httpOnly cookies with session-id regeneration on login
  (anti-fixation) and `password_changed_at` multi-session invalidation. Set
  `session.same_site` to `lax` or `strict` and `session.secure=true` in
  production.

## License

MIT © Freshost
