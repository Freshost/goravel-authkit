# goravel-authkit

Batteries-included, session-based **authentication + user management** for
[Goravel](https://www.goravel.dev) apps. Install it, register the provider,
configure it — and it auto-registers the session guard, the database migrations,
publishes the API routes, the `User` model, and (optionally) the admin
user-management endpoints for you.

Inspired by [`jeremykenedy/laravel-auth`](https://github.com/jeremykenedy/laravel-auth),
adapted to Go/Goravel idioms (static typing, code-based migrations, generated
SDK contracts). It follows the official
[goravel/example-package](https://github.com/goravel/example-package) layout. A
React/PatternFly frontend counterpart lives in `@freshost/authkit-ui`.

!!! note "Status — v1 in development"
    v1 covers the core that real projects already ship: login/logout/session,
    change-password with other-session invalidation, login rate-limiting, admin
    user-management CRUD, an audit log, TOTP two-factor, remember-me, and
    active-session tracking — across one or many independent **guards**. Later
    phases: self-registration, email verification, password reset by email, RBAC.

!!! tip "New in v0.2.0 — multi-guard"
    A **guard** is one self-contained auth domain — its own route prefix, user
    table, session guard, audit/remember/session tables, remember cookie and
    feature set. Declare several under `authkit.guards` and run them side by side
    in one Goravel app (e.g. an `admin` console and a `client` portal), or omit
    the block entirely for a single guard — the legacy single-domain setup keeps
    working unchanged. See [Configuration](configuration.md).

## What v1 gives you

| Endpoint | Description |
| --- | --- |
| `POST /api/v1/auth/login` | Session login (rate-limited), bcrypt verification |
| `POST /api/v1/auth/logout` | Destroys the session |
| `GET  /api/v1/auth/me` | Current authenticated user |
| `PUT  /api/v1/auth/password` | Change password (invalidates other sessions) |
| `POST /api/v1/auth/two-factor…` | TOTP enroll / confirm / disable / recovery + login challenge |
| `GET/POST/PUT/DELETE /api/v1/users` | Admin user management (toggleable) |
| `POST /api/v1/users/{id}/password` | Admin set-password |

Plus session-fixation protection, `password_changed_at` multi-session
invalidation, TOTP two-factor (encrypted secret + single-use recovery codes),
remember-me, active-session tracking, an `audit_logs` table + writer, an
`auth:create-user` artisan command, and a `facades.Authkit()` programmatic API.
Every one of these runs **per guard**, so a multi-guard app gets the full feature
set on each independent auth domain.

## Quick start

```bash
go get github.com/freshost/goravel-authkit
./artisan package:install github.com/freshost/goravel-authkit
# one-time: mount the routes in your routing callback (see Installation)
./artisan migrate
./artisan auth:create-user --email=admin@example.com --password=change-me
```

The provider auto-registers the session guard and the migrations from your
config; you add one line — `authkitroutes.RegisterAll(facades.Route())` — to
mount the routes. A fresh app needs **no `config/auth.go`**. See
[Installation](installation.md) for the wiring and [Configuration](configuration.md)
for the `authkit.*` settings (including multi-guard).

## Documentation

- **[Installation](installation.md)** — wiring, what `package:install` does, the
  production checklist.
- **[Configuration](configuration.md)** — every `authkit.*` key, single- and
  multi-guard setup, feature toggles, the role gate, guarding your own routes.
- **[API reference](api-reference.md)** — endpoints, request/response shapes,
  error codes, operation ids.
- **[Security](security.md)** — guarantees, operator responsibilities, v1 limits.
- **[Architecture](architecture.md)** — layering, the canonical model, the SDK loop.

## License

MIT © Freshost
