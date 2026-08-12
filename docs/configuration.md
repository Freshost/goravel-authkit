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
session guard, audit/remember/session/API-token tables, remember cookie and feature set.
An app runs N guards in one process — a single-guard app is simply N = 1.

- **Single-guard** (the default) — omit `authkit.guards` and use the top-level
  `authkit.guard` / `authkit.route_prefix`. Tables default to `users`,
  `audit_logs`, `auth_remember_tokens`, `auth_sessions`, `api_tokens`. This behaves exactly as
  before v0.2.0.
- **Multi-guard** — declare a map under `authkit.guards`; each key is a guard
  name. The top-level `authkit.*` keys (`min_password_length`, `features`,
  `roles`, `rate_limit`, `csrf`, `two_factor`, `remember`) become the **defaults for all
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
            "ip_attempts":       20,
            "account_attempts":  5,
            "password_attempts": 5,
            "window":            60, // seconds
        },
        "csrf": map[string]any{
            "enabled":         true,
            "trusted_origins": []string{},
        },
        "features": map[string]any{
            "user_management": true,
            "audit_log":       true,
            "two_factor":      true,
            "remember_me":     true,
            "sessions":        true,
            "api_tokens":      false,
        },
        "api_tokens": map[string]any{
            "allowed_scopes":            []string{},
            "default_lifetime_days":     30,
            "max_lifetime_days":         365,
            "max_per_user":              20,
            "revoke_on_password_change": true,
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
| `authkit.rate_limit.ip_attempts` | int | `20` | Authentication attempts per window per client IP |
| `authkit.rate_limit.account_attempts` | int | `5` | Login/2FA attempts per window per normalized account |
| `authkit.rate_limit.password_attempts` | int | `5` | Change-password attempts per window per authenticated user |
| `authkit.rate_limit.window` | int | `60` | Rate-limit window, seconds |
| `authkit.csrf.enabled` | bool | `true` | Fail-closed Origin/Referer verification on unsafe Authkit requests |
| `authkit.csrf.trusted_origins` | []string | `[]` | Exact additional origins accepted by the CSRF middleware |
| `authkit.features.user_management` | bool | `true` | Register the `/users` CRUD endpoints |
| `authkit.features.audit_log` | bool | `true` | Write entries to the audit-log table |
| `authkit.features.two_factor` | bool | `true` | Register the TOTP two-factor endpoints + login gate |
| `authkit.features.remember_me` | bool | `true` | Enable the persistent "remember me" login cookie |
| `authkit.features.sessions` | bool | `true` | Enable active-session tracking + the `/sessions` endpoints |
| `authkit.features.api_tokens` | bool | `false` | Enable personal API-token management and bearer authentication |
| `authkit.api_tokens.allowed_scopes` | []string | `[]` | Exact scopes users may assign; empty permits unscoped tokens only |
| `authkit.api_tokens.default_lifetime_days` | int | `30` | Default expiry shown by clients |
| `authkit.api_tokens.max_lifetime_days` | int | `365` | Maximum accepted lifetime |
| `authkit.api_tokens.max_per_user` | int | `20` | Maximum active tokens per user |
| `authkit.api_tokens.revoke_on_password_change` | bool | `true` | Revoke all personal tokens on password change/reset |
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
    "rate_limit": map[string]any{
        "ip_attempts": 20, "account_attempts": 5,
        "password_attempts": 5, "window": 60,
    },
    "csrf": map[string]any{"enabled": true, "trusted_origins": []string{}},
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
| `api_tokens_table` | `<name>_api_tokens` | This guard's personal API-token table |
| `remember_cookie_name` | `authkit_<name>_remember` | This guard's persistent-login cookie (must differ per guard on one origin) |

A guard inherits every top-level default and may **override** any of them:
`min_password_length`, `roles`, `user_management_roles`,
`features.{user_management,audit_log,two_factor,remember_me,sessions,api_tokens}`,
`rate_limit.{ip_attempts,account_attempts,password_attempts,window}`,
`csrf.{enabled,trusted_origins}`, `two_factor.{issuer,recovery_codes}`, and
`remember.lifetime_days`.

> The provider auto-registers a Goravel session guard and the migrations for each
> declared guard, so adding a guard is purely a config change — no
> `config/auth.go`, no `bootstrap/migrations.go` edit.

Registration does not execute schema changes. After adding a guard or enabling
API-token tables, run `./artisan migrate`. Removing a guard from config never
drops its tables; retain or remove that data through an explicit host-owned
migration.

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
- `ProtectToken("client", "invoices:read")` — bearer token only; every listed
  scope is required.
- `ProtectAny("client", "invoices:read")` — session or bearer token. A supplied
  invalid bearer token never falls back to a valid session. Session requests
  keep CSRF protection; bearer requests remain stateless.
- `AuthMethod`, `APITokenID`, and `TokenCan` expose the request credential type
  and token context to host authorization code.

## Feature toggles

Each toggle applies per guard (set it at the root for all guards, or inside a
guard to override):

- **`features.user_management = false`** — drops the `/users*` routes entirely
  (use for single-admin apps; `auth:create-user` still bootstraps the admin).
- **`features.audit_log = false`** — runs without writing audit entries and does
  not mount the self-service or administrator sign-in-history endpoints. The
  migration still creates the audit-log table. The administrator overview uses
  `user_management_roles` as its fail-closed access gate even when user CRUD is
  disabled.
- **`features.two_factor = false`** — drops the `/auth/two-factor*` routes and
  the two-step login gate. The migration still adds the columns.
- **`features.remember_me = false`** — drops the persistent "remember me" cookie
  and its silent re-login; login then yields a session-only cookie.
- **`features.sessions = false`** — drops active-session tracking and the
  `/auth/sessions*` endpoints (terminated-session rejection is then off).
- **`features.api_tokens = false`** — drops token management and makes
  `ProtectToken` reject bearer credentials. This is the default.

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

## Impersonation

Impersonation ("login as user") lets an authorized actor switch into another
user's session — within its own guard or across guards — and back. It is
**opt-in and fail-closed**: off by default, and a guard with no gate config
cannot impersonate (it can still be a *target* of another guard).

Two things turn it on:

- **`authkit.impersonation.enabled`** — a single global switch that mounts the
  endpoints (`POST {prefix}/auth/impersonate`, `POST {prefix}/auth/impersonate/stop`).
- A **per-guard gate** under `authkit.guards.<name>.impersonation` (or, in a
  single-guard app, at the top level `authkit.impersonation.*`) that decides who
  may impersonate into which guards:

| Key | Type | Meaning |
| --- | --- | --- |
| `roles` | []string | The actor must hold one of these roles. Empty = any authenticated user in this guard may impersonate |
| `target_guards` | []string | Guards this guard's actors may impersonate into — `"*"` = any, specific guard names, or this guard's own name for same-guard. **Empty = this guard cannot impersonate** (fail-closed) |
| `protected_roles` | []string | Target users holding one of these roles can never be impersonated |

Cross-guard adds the target guard's session alongside the actor's (one shared
cookie), so the actor stays signed in to its own guard and "stop" just drops the
target session; same-guard replaces the user, and "stop" restores the actor.

### Worked example (the demo)

The demo enables impersonation globally and lets `admin` actors impersonate users
in the `client` portal and in their own guard, but never another admin:

```go
facades.Config().Add("authkit", map[string]any{
    // Global switch.
    "impersonation": map[string]any{"enabled": true},

    "guards": map[string]any{
        "admin": map[string]any{
            "prefix":      "/api/v1",
            "users_table": "users",
            // Per-guard gate: who may impersonate, into which guards, and who is off-limits.
            "impersonation": map[string]any{
                "roles":           []string{"admin"},           // actor must be an admin
                "target_guards":   []string{"client", "admin"}, // client portal + same-guard
                "protected_roles": []string{"admin"},           // never impersonate another admin
            },
        },
        "client": map[string]any{
            "prefix":      "/api/client/v1",
            "users_table": "client_users",
            // No "impersonation" block: the client guard cannot impersonate, but
            // (being a target_guard above) its users can be impersonated by admin.
        },
    },
})
```

In a single-guard app the same keys live at the top level:

```go
"impersonation": map[string]any{
    "enabled":         true,
    "roles":           []string{"admin"},
    "target_guards":   []string{"admin"},
    "protected_roles": []string{"admin"},
},
```

### Optional host hook

The config gate handles roles / target guards / protected roles declaratively.
For finer rules a config table can't express (tenant scoping, relationship
checks), register a host hook with `authkit.RegisterImpersonationPolicy(p)` where
`p` implements `authkit.Impersonator`. It runs **only after** the config gate has
passed, so it can only ever *tighten* the decision; when no hook is registered the
config gate alone decides. See [API reference](api-reference.md) and
[security](security.md) for the hook signature and security properties.
