---
name: adopt-goravel-auth
description: Step-by-step guide for an AI agent to adopt the `github.com/freshost/goravel-auth` package into a Goravel (v1.17.x) + Vite/React app — replacing the app's hand-rolled login/logout/session/change-password/user-management with the shared package. Covers dependency wiring, the required Goravel config (bcrypt cost 12, session guard, trusted proxies), migration registration, route registration, swapping out the old auth code, the `admin_users → users` data migration, SDK regeneration, and end-to-end verification. Use when a project wants to switch its bespoke auth to goravel-auth, or when scaffolding auth into a new app in this stack.
---

# Adopting goravel-auth into a Goravel app

This skill is for an agent working **inside a consuming Goravel + Vite/React
project** (not inside the goravel-auth repo). It replaces the project's own auth
with the shared package. Read the package docs alongside this:
`docs/installation.md`, `docs/configuration.md`, `docs/security.md`,
`docs/api-reference.md`.

The package **owns the `users` and `audit_logs` tables** and a canonical `User`
model. There is no model extensibility — the app conforms to the package shape.

## Before you start — assess the target

Run these and read the results before changing anything:

1. Confirm Goravel **v1.17.x** in `go.mod` (`github.com/goravel/framework`).
2. Find the existing auth: `grep -rl "Guard(" app/ routes/` and locate the auth
   controller, service, middleware, the user model + table, and the routes.
3. Decide the **migration scenario**:
   - **A. Fresh / already `users`** — no users table yet, or a `users` table that
     already matches the canonical columns (e.g. an Auth.js-shaped schema). Easy.
   - **B. Existing `admin_users` (or other shape)** — needs a data migration to
     rename/reshape into `users`. See [Step 6B](#step-6b-data-migration-for-an-existing-table).
4. Note the existing **route paths** and **SDK operation ids** the frontend uses
   (e.g. `/admin-users` + `listAdminUsers`) — they will change to the package's
   (`/users` + `listUsers`).

Make a branch. Do not work on the default branch.

## Step 1 — Add the dependency

Published:

```bash
go get github.com/freshost/goravel-auth
```

Local dev (repo not yet public) — add to `go.mod` and `go mod tidy`:

```
require github.com/freshost/goravel-auth v0.0.0
replace github.com/freshost/goravel-auth => /absolute/path/to/goravel-auth
```

## Step 2 — Register the provider

```bash
./artisan package:install github.com/freshost/goravel-auth
```

or manually add `&auth.ServiceProvider{}` (import
`auth "github.com/freshost/goravel-auth"`) to `bootstrap/providers.go` or
`config/app.go`.

## Step 3 — Ensure the required config

- **`config/hashing.go`** must select **bcrypt, cost 12**. Verify it exists; if
  the app hashed elsewhere (e.g. bcrypt directly), this keeps existing
  `$2a$12$` hashes verifiable.
- **`config/auth.go`** must define a **session** guard whose name matches
  `authkit.guard` (default `admin`) → an `orm` provider:
  ```go
  "guards":    map[string]any{"admin": map[string]any{"driver": "session", "provider": "users"}},
  "providers": map[string]any{"users": map[string]any{"driver": "orm"}},
  ```
- **`config/session.go`** — httpOnly; production `secure=true`, `same_site` set.
- If behind a proxy/CDN, set **`http.trusted_proxies`** (rate-limit + audit IP
  depend on it — see `docs/security.md`).
- Optionally add **`config/authkit.go`** to tune prefix/guard/min-password/
  rate-limit/feature toggles (see `docs/configuration.md`).

## Step 4 — Register the migrations

In `bootstrap/migrations.go`, append the package migrations. **Order matters**
for scenario B (see Step 6B):

```go
import authmigrations "github.com/freshost/goravel-auth/migrations"

func Migrations() []schema.Migration {
    return append(authmigrations.Migrations(),
        // ...the app's own (non-auth) migrations
    )
}
```

If the app has its own `create_users` / `create_admin_users` migration, **remove
it** (the package owns that schema now) — unless you keep it for the rename in 6B.

## Step 5 — Register the routes

In the app's routes file (e.g. `routes/api.go`):

```go
import authroutes "github.com/freshost/goravel-auth/routes"

authroutes.Register(facades.Route(), authroutes.OptionsFromConfig())
```

For a single-admin app, disable user management:

```go
o := authroutes.OptionsFromConfig()
o.EnableUserManagement = false
authroutes.Register(facades.Route(), o)
```

Remove the app's own auth/user routes that this replaces.

## Step 6 — Remove the app's old auth code

Delete (or stop wiring) the now-duplicated app code, and delete references:

- the app's auth controller + user/admin controller,
- the auth/admin service + its repository,
- the session/auth middleware (`AdminAuth` etc.) — replace usages on guarded
  route groups with `middleware.Authenticated(guard)` from the package, OR keep
  using `authroutes.Register` which mounts its own guard,
- the app's `User`/`AdminUser` model + the session-regen helper (the package
  ships `helpers.RegenerateAndPersistSession`),
- the bootstrap `create-admin` command (use `auth:create-user`).

Other domain controllers that read the authenticated user id from context can
read it via `helpers.AuthUserID(ctx)` (context key `auth_user_id`), which the
package middleware sets — keep that key consistent if domain code depends on it.

### Step 6B — Data migration for an existing table

For scenario B (e.g. `admin_users`), write an **idempotent** code-based
migration that reshapes the old table into the canonical `users`, and register
it **before** the package migrations so the package's `CreateUsers` (guarded by
`HasTable("users")`) no-ops:

```go
// bootstrap/migrations.go
return append(
    []schema.Migration{&migrations.RenameAdminUsersToUsers{}}, // runs first
    authmigrations.Migrations()...,                            // CreateUsers sees "users" → skips
)
```

```go
func (r *RenameAdminUsersToUsers) Up() error {
    if facades.Schema().HasTable("users") || !facades.Schema().HasTable("admin_users") {
        return nil // already migrated, or nothing to do
    }
    // rename table, then reshape columns to match the canonical model
    facades.Orm().Query().Exec("ALTER TABLE admin_users RENAME TO users")
    facades.Orm().Query().Exec("ALTER TABLE users RENAME COLUMN password TO password_hash")
    facades.Orm().Query().Exec("ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL")
    facades.Orm().Query().Exec("ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified timestamptz")
    facades.Orm().Query().Exec("ALTER TABLE users ADD COLUMN IF NOT EXISTS image text")
    facades.Orm().Query().Exec("ALTER TABLE users ADD COLUMN IF NOT EXISTS role text NOT NULL DEFAULT 'admin'")
    facades.Orm().Query().Exec("ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now()")
    return nil
}
```

Adjust column names to the real legacy schema. **Existing bcrypt `$2a$12$`
hashes stay valid** — do not re-hash. Verify the old admin can still log in
after migrating.

## Step 7 — Regenerate the API SDK

The package controllers carry Swagger annotations with fixed operation ids
(`login`, `logout`, `getMe`, `changePassword`, `listUsers`, `createUser`,
`getUser`, `updateUser`, `deleteUser`, `setUserPassword`). Make sure swag parses
the dependency module (`swag init --parseDependency --parseInternal`), then run
the app's `make swagger` + `make generate-api`.

## Step 8 — Update the frontend (interim, until @freshost/auth-ui)

The companion `@freshost/auth-ui` package is the eventual home for the React
auth UI. Until it's adopted, point the app's existing `useAuth`/login code at the
**new generated SDK functions and routes**:

- `me` → `getMe`, admin-user ids (`listAdminUsers`, `createAdminUser`, …) →
  (`listUsers`, `createUser`, …); paths `/admin-users` → `/users`.
- Login/logout/change-password keep the same shapes (`UserResponse`,
  `MessageResponse`).

Run `pnpm type-check` and fix the renamed imports.

## Step 9 — Create the admin & verify end-to-end

```bash
./artisan migrate
./artisan auth:create-user --email=admin@example.com --password=...
cd backend && go build ./... && go test ./...
```

Then run the app and verify (read-only where the app warns about live writes):

1. **Login** with the seeded admin → 200, session cookie set.
2. **GET /auth/me** → the user.
3. **Change password** → other sessions get `401 session_expired`, this one stays.
4. **User CRUD** (if enabled) → list/create/update/delete, last-admin + self-delete
   guards fire.
5. Wrong password / unknown email → identical `401 invalid_credentials`.

## Common pitfalls

- **Swagger doesn't see the endpoints** → swag isn't parsing the dependency
  module; add `--parseDependency --parseInternal`, and ensure `routes.Register`
  is reachable from `main.go`.
- **Login 500 on hash** → missing/incorrect `config/hashing.go` (must be bcrypt
  cost 12).
- **`CreateUsers` migration fails "table exists"** → you're in scenario B but
  didn't order the rename migration first / the rename didn't run.
- **Rate-limit/audit IP wrong behind proxy** → set `http.trusted_proxies`.
- **Guard name mismatch** → `config/auth.go` guard name must equal
  `authkit.guard` / `Options.Guard`.
