# Configuration

All behaviour is tuned through one file: `config/authkit.go`, which
`package:install` writes into your app. The ServiceProvider reads it at boot and
registers the routes accordingly. Every key is optional — the package falls back
to the same defaults if a key (or the whole file) is missing. You never wire
anything in Go — registering the provider is the whole integration.

## `config/authkit.go`

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
        "user_management_roles": []string{}, // empty = open to any authenticated user
    })
}
```

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `authkit.route_prefix` | string | `/api/v1` | Prefix for all package routes |
| `authkit.guard` | string | `admin` | Goravel session guard name (must match a guard in `config/auth.go`) |
| `authkit.min_password_length` | int | `8` | Minimum new-password length |
| `authkit.rate_limit.attempts` | int | `5` | Login attempts per window per IP |
| `authkit.rate_limit.window` | int | `60` | Rate-limit window, seconds |
| `authkit.features.user_management` | bool | `true` | Register the `/users` CRUD endpoints |
| `authkit.features.audit_log` | bool | `true` | Write entries to `audit_logs` |
| `authkit.user_management_roles` | []string | `[]` | Roles allowed to use `/users` (empty = any authenticated user) |

## Feature toggles

- **`features.user_management = false`** — drops the `/users*` routes entirely
  (use for single-admin apps; `auth:create-user` still bootstraps the admin).
- **`features.audit_log = false`** — runs without writing audit entries. The
  migration still creates the `audit_logs` table.

## Gating user management by role

v1 ships **no RBAC** — by default any authenticated user can manage users. When
your app starts assigning roles, set `authkit.user_management_roles`, e.g.:

```go
"user_management_roles": []string{"admin"},
```

The package then wraps the `/users` endpoints with a `RequireRole` check: a user
whose `role` is not in the list gets `403 forbidden`. Leave it empty to keep the
v1 open behaviour. See [security](security.md) for the full picture.
