# goravel-auth

Batteries-included, session-based **authentication + user management** for
[Goravel](https://www.goravel.dev) apps. Install it, register the provider,
configure it — and it publishes the API routes, database migrations, the `User`
model, and (optionally) the admin user-management endpoints for you.

Inspired by [`jeremykenedy/laravel-auth`](https://github.com/jeremykenedy/laravel-auth),
adapted to Go/Goravel idioms (static typing, code-based migrations, generated
SDK contracts). The React/PatternFly frontend counterpart lives in
[`@freshost/auth-ui`](https://github.com/freshost/auth-ui).

> **Status:** v1 in development. v1 covers the core that real projects already
> ship: login/logout/session, change-password with other-session invalidation,
> login rate-limiting, admin user-management CRUD, and an audit log. Later
> phases: self-registration, email verification, password reset by email, RBAC.

## What v1 gives you

| Endpoint | Description |
| --- | --- |
| `POST /auth/login` | Session login (rate-limited), bcrypt verification |
| `POST /auth/logout` | Destroys the session |
| `GET  /auth/me` | Current authenticated user |
| `PUT  /auth/password` | Change password (invalidates other sessions) |
| `GET/POST/PUT/DELETE /users` | Admin user management (toggleable) |
| `POST /users/{id}/password` | Admin set-password |

Plus: session-fixation protection, `password_changed_at` multi-session
invalidation, an `audit_logs` table + writer, and an `auth:create-user` artisan
command for bootstrapping the first admin.

## Documentation

- [Installation](docs/installation.md) — full wiring (provider, config,
  migrations, routes, first admin, SDK).
- [Configuration](docs/configuration.md) — `authkit.*` keys, `routes.Options`,
  feature toggles, the `RequireRole` gate.
- [API reference](docs/api-reference.md) — endpoints, request/response shapes,
  error codes, operation ids.
- [Security model](docs/security.md) — guarantees, operator responsibilities,
  v1 limitations, audit actions.
- [Architecture](docs/architecture.md) — layering, the canonical model, Goravel
  integration, the SDK contract loop.

**Adopting into an existing app?** There is a bundled agent skill at
[`.claude/skills/adopt-goravel-auth/`](.claude/skills/adopt-goravel-auth/SKILL.md)
— copy it into your project's `.claude/skills/` and an AI agent can perform the
swap (including the `admin_users → users` data migration) step by step.

## Install

Register the provider — that is the whole integration. The provider registers
the migrations, routes, and artisan commands itself.

```bash
go get github.com/freshost/goravel-auth
./artisan package:install github.com/freshost/goravel-auth
./artisan migrate
./artisan auth:create-user --email=admin@example.com --password=change-me
```

`package:install` registers `auth.ServiceProvider` into your app and writes the
config files (`config/auth.go` — the session `admin` guard, `config/authkit.go`
— package settings, `config/hashing.go` — bcrypt cost 12). You don't append
migrations or register routes by hand — the provider does it at boot.

> **Already have a `config/auth.go` / other guards?** `package:install`
> overwrites those config files, which is right for a fresh app but not for one
> with existing auth. In that case follow the
> [adoption skill](.claude/skills/adopt-goravel-auth/SKILL.md) (merge the guard,
> migrate `admin_users → users`) instead of the plain install.

For local development before the repo is public, add a `replace` directive
(`replace github.com/freshost/goravel-auth => ../goravel-auth`) and register the
provider manually (`&auth.ServiceProvider{}` in `bootstrap/providers.go`).

## Configuration

Behaviour is tuned via optional `authkit.*` config keys (all have safe
defaults — the package works with no config at all). Either set them in a
`config/authkit.go` in your app, or pass a `routes.Options` to `Register`
directly (Options take precedence; `routes.OptionsFromConfig()` reads the keys
below).

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `authkit.route_prefix` | string | `/api/v1` | Prefix for all routes |
| `authkit.guard` | string | `admin` | Goravel session guard name |
| `authkit.min_password_length` | int | `8` | Minimum new-password length |
| `authkit.rate_limit.attempts` | int | `5` | Login attempts per window per IP |
| `authkit.rate_limit.window` | int | `60` | Rate-limit window (seconds) |
| `authkit.features.user_management` | bool | `true` | Register `/users` CRUD |
| `authkit.features.audit_log` | bool | `true` | Write audit entries |

`Register` defaults every zero-valued Option, so `Register(facades.Route(), routes.Options{})`
is safe.

## Security notes (read before deploying)

- **Hashing is bcrypt cost 12.** `package:install` writes `config/hashing.go`
  with bcrypt cost 12 (what existing `$2a$12$` hashes verify against). Keep it
  that way — the package hashes via the Goravel `Hash` facade.
- **Configure trusted proxies.** The login rate-limiter and the audit log key on
  `ctx.Request().Ip()`, which honours `X-Forwarded-For`. Behind a proxy/CDN, set
  Goravel's `http.trusted_proxies` or the limit is bypassable (and audit IPs are
  spoofable) by sending a forged header.
- **No RBAC in v1.** The `/users` management endpoints sit behind the session
  guard only — every authenticated user can manage users. Once your app assigns
  roles, gate them with `routes.Options.UserManagementRoles` (e.g.
  `[]string{"admin"}`), which adds a `RequireRole` check. True RBAC
  (roles/permissions tables) is a later phase.
- **Sessions** use httpOnly cookies with session-id regeneration on login
  (anti-fixation) and `password_changed_at` multi-session invalidation. Set
  `session.same_site` to `lax` or `strict` and `session.secure=true` in
  production.

## License

MIT © Freshost
