---
name: adopt-goravel-authkit
description: Step-by-step guide for an AI agent to adopt the `github.com/freshost/goravel-authkit` package into a Goravel (v1.17.x) + Vite/React app — replacing the app's hand-rolled login/logout/session/change-password/user-management with the shared package. Covers the one-step install for fresh apps, the careful path for apps that already have auth (merge the guard instead of overwriting config, `admin_users → users` data reshape, removing the old code), SDK regeneration, the React companion `@freshost/authkit-ui` (drop-in login/account/2FA/user-management UI), and end-to-end verification. Use when a project wants to switch its bespoke auth to goravel-authkit, or when scaffolding auth into a new app in this stack.
---

# Adopting goravel-authkit into a Goravel app

For an agent working **inside a consuming Goravel + Vite/React project**. Read
the package docs alongside this: `docs/installation.md`, `docs/configuration.md`,
`docs/security.md`, `docs/api-reference.md`.

The package **owns the `users` and `audit_logs` tables** and a canonical `User`
model — there is no model extensibility, the app conforms to the package shape.
Registering `authkit.ServiceProvider` registers the migrations + the
`auth:create-user` command. Two things are wired app-side in `bootstrap/app.go`:
global **`StartSession()`** middleware and a one-line
**`authkitroutes.Register(facades.Route(), authkitroutes.OptionsFromConfig())`**
in the routing callback (the provider can't register routes itself — Goravel
rebuilds the HTTP engine when global middleware is set, *after* providers boot,
so provider-registered routes are discarded; the routing callback runs after
that rebuild). The questions are getting there without clobbering existing auth,
and adding those two lines.

## Decide the scenario first

- **Fresh app** (no existing auth, no `users`/`admin_users` table) → use
  [Path A](#path-a--fresh-app). One command.
- **Existing auth** (already has a user table, a guard, login code) → use
  [Path B](#path-b--existing-app). `package:install` would **overwrite** your
  `config/auth.go`, so do it carefully.

Always work on a branch.

## Path A — fresh app

```bash
go get github.com/freshost/goravel-authkit
./artisan package:install github.com/freshost/goravel-authkit
# then add the two lines below to bootstrap/app.go
./artisan migrate
./artisan auth:create-user --email=admin@example.com --password=change-me
```

`package:install` registers the provider and writes `config/auth.go`,
`config/authkit.go`, `config/hashing.go`. Then wire sessions + routes in
`bootstrap/app.go`:

```go
import (
	"github.com/goravel/framework/contracts/foundation/configuration"
	sessionmiddleware "github.com/goravel/framework/session/middleware"
	authkitroutes "github.com/freshost/goravel-authkit/routes"
)

foundation.Setup().
	WithMiddleware(func(h configuration.Middleware) {
		h.Append(sessionmiddleware.StartSession())
	}).
	WithRouting(func() {
		routes.Web()
		authkitroutes.Register(facades.Route(), authkitroutes.OptionsFromConfig())
	}).
	// ...providers, migrations, config
```

A complete runnable reference is the `authkit-ui/demo/backend`. Verify with
[Step V](#step-v--verify).

## Path B — existing app

### B1. Add the dependency + register the provider manually

Do **not** run `package:install` (it overwrites config). Add the module
(`go get`, or a `replace` directive for local dev) and add the provider by hand:

```go
// bootstrap/providers.go
import authkit "github.com/freshost/goravel-authkit"
// ... &authkit.ServiceProvider{},
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

The provider wires migrations + the command itself; you add the global
`StartSession()` middleware and the one-line `authkitroutes.Register(...)` in
`bootstrap/app.go` (see Path A). Migration ordering for the reshape is handled by
doing the SQL in B3 **before** the first `migrate` (above), not by interleaving a
migration.

## Step S — regenerate the API SDK

The controllers carry Swagger annotations with fixed operation ids (`login`,
`logout`, `getMe`, `changePassword`, `listUsers`, `createUser`, `getUser`,
`updateUser`, `deleteUser`, `setUserPassword`, plus the two-factor ids
`twoFactorChallenge`, `enableTwoFactor`, `confirmTwoFactor`, `disableTwoFactor`,
`getTwoFactorRecoveryCodes`, `regenerateTwoFactorRecoveryCodes`). Run swag with
`--parseDependency --parseInternal` so the package module is scanned, then your
`make swagger` + `make generate-api`.

## Step F — frontend (`@freshost/authkit-ui`)

The companion package `@freshost/authkit-ui` replaces the app's hand-rolled
login / account / 2FA / user-management UI. It talks to the backend through its
**own typed client** over the stable authkit routes — it does **not** depend on
the app's generated SDK, so adopting it is independent of Step S. Read its
README for the full API.

1. **Install** (peer deps already present in this stack: `@freshost/ui`, React,
   `react-router`, `@tanstack/react-query`, `react-i18next`). Until it's
   published, add the packed tarball:
   ```bash
   pnpm add @freshost/authkit-ui     # or: pnpm add /path/to/freshost-authkit-ui-*.tgz
   ```
2. **Wire the provider** inside the existing `QueryClientProvider` + i18n +
   router. Build a `notify` adapter from whatever the app already has:
   - imperative store: `{ success: notify.success, error: notify.danger }`
   - `useToast()` context: wrap `toast({ variant, title })` in `success`/`error`
     (memoize where the hook is in scope).
   Pass `baseURL` (the app's `/api/v1`), `branding`, and `routes`.
3. **Swap the pages**: replace the app's `LoginPage` / account / admin-users
   pages and `useAuth`/`useAdminUsers` hooks with the package's `LoginPage`,
   `AuthGuard`, `AccountPage`/`ChangePasswordModal`, `UsersPage`, and the 2FA
   components (`TwoFactorSetup`, `DisableTwoFactor`, `RecoveryCodes`). Delete the
   old toast-coupled auth hooks; the package's hooks toast via your adapter.
4. **Keep the app's `QueryClient` defaults** — the package sets only per-query
   options. Don't add global `staleTime`/`retry` for it.

**Interim fallback** (if you must keep the app's own UI for now): point the
existing `useAuth` code at the new SDK ids/paths — `me`→`getMe`,
`listAdminUsers`→`listUsers`, `/admin-users`→`/users`; login/logout/change-
password keep the same `UserResponse`/`MessageResponse` shapes.

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
