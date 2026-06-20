# goravel-authkit

Batteries-included, session-based **authentication + user management** for
[Goravel](https://www.goravel.dev) apps. Install it, register the provider,
configure it — and it publishes the API routes, database migrations, the `User`
model, and (optionally) the admin user-management endpoints for you.

Inspired by [`jeremykenedy/laravel-auth`](https://github.com/jeremykenedy/laravel-auth),
adapted to Go/Goravel idioms (static typing, code-based migrations, generated
SDK contracts). It follows the official
[goravel/example-package](https://github.com/goravel/example-package) layout. A
React/PatternFly frontend counterpart lives in `@freshost/auth-ui`.

!!! note "Status — v1 in development"
    v1 covers the core that real projects already ship: login/logout/session,
    change-password with other-session invalidation, login rate-limiting, admin
    user-management CRUD, and an audit log. Later phases: self-registration,
    email verification, password reset by email, RBAC.

## What v1 gives you

| Endpoint | Description |
| --- | --- |
| `POST /api/v1/auth/login` | Session login (rate-limited), bcrypt verification |
| `POST /api/v1/auth/logout` | Destroys the session |
| `GET  /api/v1/auth/me` | Current authenticated user |
| `PUT  /api/v1/auth/password` | Change password (invalidates other sessions) |
| `GET/POST/PUT/DELETE /api/v1/users` | Admin user management (toggleable) |
| `POST /api/v1/users/{id}/password` | Admin set-password |

Plus session-fixation protection, `password_changed_at` multi-session
invalidation, an `audit_logs` table + writer, an `auth:create-user` artisan
command, and a `facades.Authkit()` programmatic API.

## Quick start

```bash
go get github.com/freshost/goravel-authkit
./artisan package:install github.com/freshost/goravel-authkit
./artisan migrate
./artisan auth:create-user --email=admin@example.com --password=change-me
```

That's the whole integration — see [Installation](installation.md) for the
details and [Configuration](configuration.md) for the `authkit.*` settings.

## Documentation

- **[Installation](installation.md)** — wiring, what `package:install` does, the
  production checklist.
- **[Configuration](configuration.md)** — every `authkit.*` key, feature toggles,
  the role gate.
- **[API reference](api-reference.md)** — endpoints, request/response shapes,
  error codes, operation ids.
- **[Security](security.md)** — guarantees, operator responsibilities, v1 limits.
- **[Architecture](architecture.md)** — layering, the canonical model, the SDK loop.

## License

MIT © Freshost
