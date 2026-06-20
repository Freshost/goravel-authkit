# Configuration

`package:install` writes a `config/authkit.go` into your app; the ServiceProvider
reads it at boot (via `routes.OptionsFromConfig()`) to register the routes. Edit
that file to tune behaviour. Every key is optional — the package falls back to
the same defaults if a key (or the whole file) is missing.

For advanced cases you can bypass the provider and mount the routes yourself with
an explicit `routes.Options` (see the "Manual wiring" section of
[installation](installation.md)); Options passed to `routes.Register` win over
config, and any zero-valued Option falls back to `DefaultOptions()`.

## `authkit.*` config keys

The published `config/authkit.go` looks like this (all keys optional):

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
        },
    })
}
```

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `authkit.route_prefix` | string | `/api/v1` | Prefix for all package routes |
| `authkit.guard` | string | `admin` | Goravel session guard name |
| `authkit.min_password_length` | int | `8` | Minimum new-password length |
| `authkit.rate_limit.attempts` | int | `5` | Login attempts per window per IP |
| `authkit.rate_limit.window` | int | `60` | Rate-limit window, seconds |
| `authkit.features.user_management` | bool | `true` | Register `/users` CRUD |
| `authkit.features.audit_log` | bool | `true` | Write audit entries |

## `routes.Options`

```go
type Options struct {
    Prefix               string        // e.g. "/api/v1"
    Guard                string        // session guard name
    MinPasswordLength    int
    RateLimitAttempts    int
    RateLimitWindow      time.Duration
    EnableUserManagement bool
    EnableAuditLog       bool
    UserManagementRoles  []string      // gate /users behind a role (see below)
}
```

Helpers:

- `routes.DefaultOptions()` — the baked-in defaults.
- `routes.OptionsFromConfig()` — `DefaultOptions()` overlaid with any `authkit.*`
  keys present.

Examples:

```go
// Config-driven (recommended):
authroutes.Register(facades.Route(), authroutes.OptionsFromConfig())

// Single-admin app: no user management, audit on.
o := authroutes.DefaultOptions()
o.EnableUserManagement = false
authroutes.Register(facades.Route(), o)

// Multi-admin with a role gate on user management (once you assign roles):
o := authroutes.OptionsFromConfig()
o.UserManagementRoles = []string{"admin"}
authroutes.Register(facades.Route(), o)
```

## Gating user management by role (`UserManagementRoles`)

v1 ships **no RBAC** — by default any authenticated user can manage users. When
your app starts assigning roles, set `UserManagementRoles`. The package then
wraps the `/users` endpoints with a `RequireRole` middleware: a user whose
`role` is not in the list gets `403 forbidden`. Leave it empty to keep the v1
open behaviour. See [security](security.md) for the full picture.

## Feature toggles

- **`EnableUserManagement = false`** — drops the `/users*` routes entirely (use
  for single-admin apps; the `auth:create-user` command still bootstraps the
  admin).
- **`EnableAuditLog = false`** — controllers run without writing audit entries
  (no `audit_logs` writes). The migration still creates the table.
