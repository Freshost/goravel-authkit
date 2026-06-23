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
            "two_factor":      true,
        },
        "two_factor": map[string]any{
            "issuer":         "", // defaults to the app name
            "recovery_codes": 8,
        },
        "user_management_roles": []string{"admin"}, // fail-closed: /users is admin-only
        "roles":                 []string{"admin", "user"}, // assignable role values
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
| `authkit.features.two_factor` | bool | `true` | Register the TOTP two-factor endpoints + login gate |
| `authkit.two_factor.issuer` | string | `""` | Issuer shown in the authenticator app (empty = app name) |
| `authkit.two_factor.recovery_codes` | int | `8` | Recovery codes generated on confirmation |
| `authkit.user_management_roles` | []string | `["admin"]` | Roles allowed to use `/users`. Fail-closed: `/users` is always gated; an empty list falls back to `["admin"]`, never to "any authenticated user" |
| `authkit.roles` | []string | `["admin","user"]` | Assignable role values (create/update reject anything outside it; empty = any). New users default to the first non-admin role, else `user` |

## Feature toggles

- **`features.user_management = false`** — drops the `/users*` routes entirely
  (use for single-admin apps; `auth:create-user` still bootstraps the admin).
- **`features.audit_log = false`** — runs without writing audit entries. The
  migration still creates the `audit_logs` table.
- **`features.two_factor = false`** — drops the `/auth/two-factor*` routes and
  the two-step login gate. The migration still adds the columns.

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
