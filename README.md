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

`config/authkit.go` (published) controls route prefix, guard name, minimum
password length, login rate-limit, and feature toggles
(`user_management`, `audit_log`).

## License

MIT © Freshost
