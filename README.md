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

```bash
go get github.com/freshost/goravel-auth
./artisan package:install github.com/freshost/goravel-auth
```

This registers `auth.ServiceProvider` and publishes `config/authkit.go` plus the
migrations. Then:

1. Point your `config/auth.go` guard at the package model (the installer wires a
   session `admin` guard → `users` ORM provider).
2. Append the package migrations to your registry:
   ```go
   // bootstrap/migrations.go
   import authmigrations "github.com/freshost/goravel-auth/migrations"
   func Migrations() []schema.Migration {
       return append(authmigrations.Migrations(), /* your migrations */ )
   }
   ```
3. Register the routes:
   ```go
   // routes/api.go
   import authroutes "github.com/freshost/goravel-auth/routes"
   authroutes.Register(facades.Route(), authroutes.Options{ /* prefix, middleware */ })
   ```
4. Migrate and create the first admin:
   ```bash
   ./artisan migrate
   ./artisan auth:create-user --email=admin@example.com --password=secret
   ```

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

- **Hashing config is required.** The package hashes via the Goravel `Hash`
  facade, so your app must ship a `config/hashing.go` selecting **bcrypt with
  cost 12** (the value both reference apps use, and what existing `$2a$12$`
  hashes verify against). Without a hashing config, login and password changes
  cannot hash/verify.
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
