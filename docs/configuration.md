# Configuration

All behaviour is tuned through one file: `config/authkit.go`, which
`package:install` writes into your app. The ServiceProvider reads it at boot —
auto-registering a Goravel session guard and the migrations per guard — and
`authkitroutes.RegisterAll(facades.Route())` in your routing callback mounts the
routes. Every key is optional; the package falls back to the same defaults if a
key (or the whole file) is missing. **The only two things you configure are this
file and that one-line route mount** — there is no `config/auth.go` to write.

## Guards

A **guard** is one self-contained auth domain: its route prefix, user table,
session guard, audit/remember/session tables, remember cookie and feature set.
An app runs N guards in one process — a single-guard app is simply N = 1.

- **Single-guard** (the default) — omit `authkit.guards` and use the top-level
  `authkit.guard` / `authkit.route_prefix`. Tables default to `users`,
  `audit_logs`, `auth_remember_tokens`, `auth_sessions`. This behaves exactly as
  before v0.2.0.
- **Multi-guard** — declare a map under `authkit.guards`; each key is a guard
  name. The top-level `authkit.*` keys (`min_password_length`, `features`,
  `roles`, `rate_limit`, `two_factor`, `remember`) become the **defaults for all
  guards**, and each guard may override them.

## `config/authkit.go` (single guard)

```go
package config

import "github.com/goravel/framework/facades"

func init() {
    facades.Config().Add("authkit", map[string]any{
        "route_prefix":        "/api/v1",
        "guard":               "admin",
        "min_password_length": 8,
        "rate_limit": map[string]any{
            "attempts": 5,
            "window":   60, // seconds
        },
        "features": map[string]any{
            "user_management": true,
            "audit_log":       true,
            "two_factor":      true,
            "remember_me":     true,
            "sessions":        true,
        },
        "two_factor": map[string]any{
            "issuer":         "", // defaults to the app name
            "recovery_codes": 8,
        },
        "remember": map[string]any{
            "lifetime_days": 30,
        },
        "user_management_roles": []string{"admin"}, // fail-closed: /users is admin-only
        "roles":                 []string{"admin", "user"}, // assignable role values
    })
}
```

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `authkit.route_prefix` | string | `/api/v1` | Prefix for all package routes (single-guard) |
| `authkit.guard` | string | `admin` | Goravel session guard name (auto-registered by the provider) |
| `authkit.min_password_length` | int | `8` | Minimum new-password length |
| `authkit.rate_limit.attempts` | int | `5` | Login attempts per window per IP |
| `authkit.rate_limit.window` | int | `60` | Rate-limit window, seconds |
| `authkit.features.user_management` | bool | `true` | Register the `/users` CRUD endpoints |
| `authkit.features.audit_log` | bool | `true` | Write entries to the audit-log table |
| `authkit.features.two_factor` | bool | `true` | Register the TOTP two-factor endpoints + login gate |
| `authkit.features.remember_me` | bool | `true` | Enable the persistent "remember me" login cookie |
| `authkit.features.sessions` | bool | `true` | Enable active-session tracking + the `/sessions` endpoints |
| `authkit.two_factor.issuer` | string | `""` | Issuer shown in the authenticator app (empty = app name) |
| `authkit.two_factor.recovery_codes` | int | `8` | Recovery codes generated on confirmation |
| `authkit.remember.lifetime_days` | int | `30` | How long a remember cookie stays valid (sliding on use) |
| `authkit.user_management_roles` | []string | `["admin"]` | Roles allowed to use `/users`. Fail-closed: `/users` is always gated; an empty list falls back to `["admin"]`, never to "any authenticated user" |
| `authkit.roles` | []string | `["admin","user"]` | Assignable role values (create/update reject anything outside it; empty = any). New users default to the first non-admin role, else `user` |

## `config/authkit.go` (two guards)

Declare auth domains under `authkit.guards`. The top-level keys above apply to
every guard as defaults; each guard sets its own `prefix` and (usually)
`users_table`, and may override any default. Here an `admin` console and a
`client` portal run side by side:

```go
facades.Config().Add("authkit", map[string]any{
    // Top-level keys are the DEFAULTS inherited by every guard.
    "min_password_length": 8,
    "rate_limit": map[string]any{"attempts": 5, "window": 60},
    "features": map[string]any{
        "user_management": true,
        "audit_log":       true,
        "two_factor":      true,
        "remember_me":     true,
        "sessions":        true,
    },
    "roles":                 []string{"admin", "user"},
    "user_management_roles": []string{"admin"},

    "guards": map[string]any{
        "admin": map[string]any{
            "prefix":      "/api/v1",
            "users_table": "users", // keep the default table names
        },
        "client": map[string]any{
            "prefix":      "/api/client/v1",
            "users_table": "client_users",
            // Per-guard overrides (see below): the client portal wants longer
            // passwords and no two-factor.
            "min_password_length": 12,
            "features": map[string]any{
                "two_factor": false,
            },
        },
    },
})
```

`authkitroutes.RegisterAll(facades.Route())` mounts both — the same one-liner
whether you declare one guard or ten.

### Per-guard keys

Each entry under `authkit.guards.<name>` accepts:

| Key | Default | Meaning |
| --- | --- | --- |
| `prefix` | — | Route prefix for this guard (e.g. `/api/client/v1`) |
| `users_table` | `<name>_users` | This guard's user table |
| `audit_table` | `<name>_audit_logs` | This guard's audit-log table |
| `remember_tokens_table` | `<name>_remember_tokens` | This guard's remember-token table |
| `sessions_table` | `<name>_auth_sessions` | This guard's active-session table |
| `remember_cookie_name` | `authkit_<name>_remember` | This guard's persistent-login cookie (must differ per guard on one origin) |

A guard inherits every top-level default and may **override** any of them:
`min_password_length`, `roles`, `user_management_roles`,
`features.{user_management,audit_log,two_factor,remember_me,sessions}`,
`rate_limit.{attempts,window}`, `two_factor.{issuer,recovery_codes}`, and
`remember.lifetime_days`.

> The provider auto-registers a Goravel session guard and the migrations for each
> declared guard, so adding a guard is purely a config change — no
> `config/auth.go`, no `bootstrap/migrations.go` edit.

### Opting out of auto-wiring

If you'd rather own the wiring yourself:

- `authkit.register_guards = false` — the provider stops registering session
  guards; you define them in `config/auth.go`.
- `authkit.register_migrations = false` — the provider stops registering
  migrations; register `migrations.ForTables(...)` yourself.

## Guarding your own routes

To put a host route behind one of authkit's guards — the analogue of Laravel's
`auth:guard` — apply the middleware chain from `Protect`:

```go
import authkitroutes "github.com/freshost/goravel-authkit/routes"

facades.Route().Prefix("/api/client/v1").
    Middleware(authkitroutes.Protect("client")...).
    Group(func(r route.Router) {
        r.Get("/invoices", func(ctx contractshttp.Context) contractshttp.Response {
            userID := authkitroutes.AuthUserID(ctx) // the logged-in "client" user's uuid
            // ... scope your query to userID
        })
    })
```

- `Protect("client")` — starts the session and authenticates the request against
  the `client` guard's user table.
- `ProtectRole("client", "admin")` — the same, plus a role gate (the user's role
  must be one of the listed roles).
- `AuthUserID(ctx)` — inside a protected handler, returns the authenticated
  user's `uuid.UUID` (or `uuid.Nil` if none).

## Feature toggles

Each toggle applies per guard (set it at the root for all guards, or inside a
guard to override):

- **`features.user_management = false`** — drops the `/users*` routes entirely
  (use for single-admin apps; `auth:create-user` still bootstraps the admin).
- **`features.audit_log = false`** — runs without writing audit entries. The
  migration still creates the audit-log table.
- **`features.two_factor = false`** — drops the `/auth/two-factor*` routes and
  the two-step login gate. The migration still adds the columns.
- **`features.remember_me = false`** — drops the persistent "remember me" cookie
  and its silent re-login; login then yields a session-only cookie.
- **`features.sessions = false`** — drops active-session tracking and the
  `/auth/sessions*` endpoints (terminated-session rejection is then off).

## Gating user management by role

The `/users` endpoints are **admin-gated by default (fail-closed)**:
`authkit.user_management_roles` defaults to `["admin"]`, and the gate is always
mounted — a user whose `role` is not in the list gets `403 forbidden`. An empty
list does **not** open the endpoints; it falls back to `["admin"]`. The
single-admin bootstrap still works because `auth:create-user` mints an `admin`.

To allow another role to manage users, add it to the list:

```go
"user_management_roles": []string{"admin", "manager"},
```

New users are never silently made admins: a create with no explicit `role` gets
the first configured non-management role (else `user`). See
[security](security.md) for the full picture.
