---
name: adopt-goravel-auth
description: Step-by-step guide for an AI agent to adopt the `github.com/freshost/goravel-auth` package into a Goravel (v1.17.x) + Vite/React app — replacing the app's hand-rolled login/logout/session/change-password/user-management with the shared package. Covers the one-step install for fresh apps, the careful path for apps that already have auth (merge the guard instead of overwriting config, `admin_users → users` data reshape, removing the old code), SDK regeneration, and end-to-end verification. Use when a project wants to switch its bespoke auth to goravel-auth, or when scaffolding auth into a new app in this stack.
---

# Adopting goravel-auth into a Goravel app

For an agent working **inside a consuming Goravel + Vite/React project**. Read
the package docs alongside this: `docs/installation.md`, `docs/configuration.md`,
`docs/security.md`, `docs/api-reference.md`.

The package **owns the `users` and `audit_logs` tables** and a canonical `User`
model — there is no model extensibility, the app conforms to the package shape.
Registering `auth.ServiceProvider` is the whole integration: the provider
registers the migrations, routes, and commands itself. The only question is how
to get there without clobbering existing auth.

## Decide the scenario first

- **Fresh app** (no existing auth, no `users`/`admin_users` table) → use
  [Path A](#path-a--fresh-app). One command.
- **Existing auth** (already has a user table, a guard, login code) → use
  [Path B](#path-b--existing-app). `package:install` would **overwrite** your
  `config/auth.go`, so do it carefully.

Always work on a branch.

## Path A — fresh app

```bash
go get github.com/freshost/goravel-auth
./artisan package:install github.com/freshost/goravel-auth
./artisan migrate
./artisan auth:create-user --email=admin@example.com --password=change-me
```

`package:install` registers the provider and writes `config/auth.go`,
`config/authkit.go`, `config/hashing.go`. The provider registers migrations +
routes + the command at boot. Done — verify with [Step V](#step-v--verify).

## Path B — existing app

### B1. Add the dependency + register the provider manually

Do **not** run `package:install` (it overwrites config). Add the module
(`go get`, or a `replace` directive for local dev) and add the provider by hand:

```go
// bootstrap/providers.go
import auth "github.com/freshost/goravel-auth"
// ... &auth.ServiceProvider{},
```

### B2. Reconcile config (merge, don't overwrite)

- **`config/auth.go`** — ensure a **session** guard whose name matches
  `authkit.guard` (default `admin`) → an `orm` provider named `users`:
  ```go
  "guards":    map[string]any{"admin": map[string]any{"driver": "session", "provider": "users"}},
  "providers": map[string]any{"users": map[string]any{"driver": "orm"}},
  ```
  Merge this into your existing guards — don't drop other guards.
- **`config/hashing.go`** — must be **bcrypt cost 12** (keeps existing `$2a$12$`
  hashes verifiable). Copy from the package's `setup/config/hashing.go` if absent.
- **`config/authkit.go`** — optional; copy from `setup/config/authkit.go` to tune
  prefix / rate-limit / feature toggles. For a single-admin app set
  `features.user_management = false`.
- If behind a proxy/CDN, set `http.trusted_proxies` (see `docs/security.md`).

### B3. Reshape the existing table to `users` BEFORE the first migrate

The provider auto-registers `CreateUsers`, which is guarded by
`HasTable("users")` — so if `users` already exists in the canonical shape,
`CreateUsers` no-ops. Migrations run in **registration order**, and the
provider's registration vs your app's is not ordered reliably, so the safe move
is to reshape **before** running `migrate` (a one-off SQL step or a script),
not as an interleaved migration.

For an existing `admin_users` table (idempotent SQL — adjust to your real
columns; existing bcrypt `$2a$12$` hashes stay valid, do NOT re-hash):

```sql
ALTER TABLE admin_users RENAME TO users;
ALTER TABLE users RENAME COLUMN password TO password_hash;
ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified timestamptz;
ALTER TABLE users ADD COLUMN IF NOT EXISTS image text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS role text NOT NULL DEFAULT 'admin';
ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();
```

Canonical columns: `id (uuid pk)`, `name text null`, `email text unique`,
`email_verified timestamptz null`, `image text null`, `password_hash text null`,
`password_changed_at timestamptz`, `role text default 'admin'`, `created_at`,
`updated_at`. Then `./artisan migrate` (CreateUsers sees `users` → skips;
CreateAuditLogs creates `audit_logs`).

### B4. Remove the app's old auth code

Delete (or stop wiring) the now-duplicated code and its references:

- the app's auth + user/admin **controllers**, the auth/admin **service** + its
  repository, the session/auth **middleware** (`AdminAuth` etc.), the app's
  `User`/`AdminUser` **model**, the session-regen helper, and the bootstrap
  `create-admin` command (use `auth:create-user`).
- remove the app's auth/user **routes** — the package provider mounts its own.
- domain controllers that read the authenticated user id from context can use
  `helpers.AuthUserID(ctx)` (context key `auth_user_id`, set by the package
  middleware) — keep that key consistent if domain code depends on it.

If you need custom route mounting or migration ordering, the building blocks are
exported (`routes.Register`, `migrations.Migrations()`) — see the "Manual
wiring" section of `docs/installation.md`.

## Step S — regenerate the API SDK

The controllers carry Swagger annotations with fixed operation ids (`login`,
`logout`, `getMe`, `changePassword`, `listUsers`, `createUser`, `getUser`,
`updateUser`, `deleteUser`, `setUserPassword`). Run swag with `--parseDependency
--parseInternal` so the package module is scanned, then your `make swagger` +
`make generate-api`.

## Step F — frontend (interim, until @freshost/auth-ui)

Point the app's existing `useAuth`/login code at the **new SDK functions and
routes** until the companion `@freshost/auth-ui` package is adopted:

- `me` → `getMe`; admin-user ids (`listAdminUsers`, …) → (`listUsers`, …); paths
  `/admin-users` → `/users`.
- Login/logout/change-password keep the same shapes (`UserResponse`,
  `MessageResponse`). Run `pnpm type-check` and fix renamed imports.

## Step V — verify

```bash
cd backend && go build ./... && go test ./...
./artisan migrate
./artisan auth:create-user --email=admin@example.com --password=...
```

Then run the app and verify (read-only where the app warns about live writes):

1. **Login** with the seeded admin → 200, session cookie set.
2. **GET /auth/me** → the user.
3. **Change password** → other sessions get `401 session_expired`, this one stays.
4. **User CRUD** (if enabled) → list/create/update/delete; last-admin +
   self-delete guards fire.
5. Wrong password / unknown email → identical `401 invalid_credentials`.
6. **Existing admin still logs in** with the old password (Path B).

## Common pitfalls

- **Ran `package:install` on an existing app** → it overwrote `config/auth.go`;
  restore your other guards (Path B reconciles config by hand).
- **`CreateUsers` runs and you end up with an empty `users` + orphaned
  `admin_users`** → you reshaped too late; do the SQL reshape in B3 **before**
  the first `migrate`.
- **Login 500 on hash** → `config/hashing.go` not bcrypt cost 12.
- **Swagger doesn't see the endpoints** → add `--parseDependency --parseInternal`.
- **Rate-limit/audit IP wrong behind proxy** → set `http.trusted_proxies`.
- **Guard name mismatch** → `config/auth.go` guard name must equal
  `authkit.guard`.
