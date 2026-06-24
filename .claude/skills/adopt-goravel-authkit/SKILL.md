---
name: adopt-goravel-authkit
description: Step-by-step guide for an AI agent to adopt the `github.com/freshost/goravel-authkit` package (v0.2.0 "multi-guard") into a Goravel (v1.17.x) + Vite/React app — replacing the app's hand-rolled login/logout/session/change-password/user-management with the shared package. Covers the one-step install for fresh apps, the careful path for apps that already have auth (the provider auto-registers the session guard(s) and migrations, so there is no longer a `config/auth.go` to overwrite), the multi-guard path for apps with two separate user domains (e.g. `accounts` + `admin_users` — declare two guards instead of merging tables), protecting the host's own routes with a guard, programmatic user creation, the React companion `@freshost/authkit-ui`, and end-to-end verification. Use when a project wants to switch its bespoke auth to goravel-authkit, or when scaffolding auth into a new app in this stack.
---

# Adopting goravel-authkit into a Goravel app

For an agent working **inside a consuming Goravel + Vite/React project**. Read
the package docs alongside this: `docs/installation.md`, `docs/configuration.md`,
`docs/security.md`, `docs/api-reference.md`.

As of **v0.2.0** the package is **multi-guard**: a host declares its auth domains
as **guards** under `authkit.guards` in `config/authkit.go`, and the
ServiceProvider **auto-registers** a Goravel session guard and the migrations for
each declared guard at boot. So adoption is now genuinely small:

- There is **no `config/auth.go` to write or overwrite** — the provider registers
  each guard (a `session` driver over a shared `authkit_orm` provider) without
  clobbering a guard the host already defined. (`package:install` still makes a
  harmless additive edit to it if the file exists, but it is not required.)
- The migrations are auto-registered too — **no edit to `bootstrap/migrations.go`**.
- Routes mount in **one line** in the routing callback:
  `authkitroutes.RegisterAll(facades.Route())`. This iterates every declared guard
  (or the single default guard when none are declared). The package starts its own
  session (`StartSession` on each guard's `/auth` group), so **no global
  `StartSession` / `WithMiddleware` is needed**.

Register from the **routing callback** (not the provider's `Boot`): any global
`WithMiddleware` the app adds rebuilds the HTTP engine *after* providers boot and
discards routes a provider registered in `Boot`; the routing callback runs after
that rebuild, so the routes survive.

The package owns a canonical `User` shape (no model extensibility — the app
conforms), but each guard points at its **own** user table, so two domains coexist
without merging tables. Opt out of either auto-step if the host owns those pieces:
`authkit.register_guards = false` / `authkit.register_migrations = false`.

## Decide the scenario first

- **Fresh app** (no existing auth, no user table) → [Path A](#path-a--fresh-app).
  One command + one line.
- **Existing auth, one user domain** (one user table, one login flow) →
  [Path B](#path-b--existing-app-one-user-domain). Single guard, reshape the one
  table.
- **Existing auth, two separate user domains** (e.g. `accounts` for customers +
  `admin_users` for staff) → [Path C](#path-c--multiple-user-domains-multi-guard).
  Declare **two guards** — do **not** merge the tables.

Always work on a branch.

## Path A — fresh app

```bash
go get github.com/freshost/goravel-authkit
./artisan package:install github.com/freshost/goravel-authkit
# then add the one line below to your routing callback
./artisan migrate
./artisan auth:create-user --email=admin@example.com --password=change-me
```

`package:install` registers the provider and writes `config/authkit.go` (it does
**not** require `config/auth.go`). Then mount the routes in `bootstrap/app.go` —
no global session middleware, the package starts its own session:

```go
import (
	authkitroutes "github.com/freshost/goravel-authkit/routes"
)

foundation.Setup().
	WithRouting(func() {
		routes.Web()
		// Mounts every authkit guard (or the single default). Each guard starts
		// its own session on its /auth group — no global StartSession needed.
		authkitroutes.RegisterAll(facades.Route())
	}).
	// ...providers, migrations, config
```

The provider auto-registers the session guard and the migrations from
`config/authkit.go`, so a fresh app needs **no `config/auth.go`** and no edit to
`bootstrap/migrations.go`. (If you want bcrypt to match the rest of this stack,
set `rounds: 12` in `config/hashing.go`.)

> If the app has its *own* session-backed routes, add `StartSession` per-group on
> those (or globally). A global `StartSession` is harmless to the package — it's
> idempotent, so the package's group-level start is skipped when a session already
> exists.

A complete runnable reference is the `goravel-authkit/demo` backend (and the
`authkit-ui/demo/backend`). Verify with [Step V](#step-v--verify).

## Path B — existing app, one user domain

### B1. Add the dependency + register the provider

For local dev (repo not yet public) add a `replace` directive and register the
provider by hand; once published, `go get` + `package:install` does both:

```go
// bootstrap/providers.go
import authkit "github.com/freshost/goravel-authkit"
// ... &authkit.ServiceProvider{},
```

`package:install` is now safe to run even on an existing app — it makes only
**additive** edits (registers the provider, writes the package-owned
`config/authkit.go`, and *if* `config/auth.go`/`config/hashing.go` exist, adds the
`admin` guard / `users` provider / bcrypt `rounds: 12` without dropping your other
entries). You can also just do those by hand.

### B2. Configure (single-guard mode)

Keep the **top-level** `authkit.*` config (no `authkit.guards` block) — this is
single-guard mode and behaves exactly as before. Copy `config/authkit.go` from the
package's `setup/config/authkit.go` and tune `route_prefix`, `rate_limit`,
features, `roles`. For a single-admin app set `features.user_management = false`.

- **`config/auth.go`** — **not required.** The provider auto-registers the `admin`
  session guard over the shared `authkit_orm` provider. If the host already
  defines a guard whose name matches `authkit.guard` (default `admin`), that
  hand-written guard **wins** and is left untouched. Only set
  `authkit.register_guards = false` if you want to own `config/auth.go` entirely.
- **`config/hashing.go`** — set **bcrypt cost 12** (`rounds: 12`) to keep existing
  `$2a$12$` hashes verifiable.
- If behind a proxy/CDN, set `http.trusted_proxies` (see `docs/security.md`).

### B3. Reshape the existing table to the canonical `users` shape

The package's `CreateUsers` migration is idempotent: it **skips when the table
already exists**, and the column-adding migrations (`AddTwoFactorToUsers`,
`AddDisabledAtToUsers`, etc.) **skip when the column already exists**. So you do
**not** need to drop your table — reshape it to carry authkit's required columns,
then let `migrate` add anything missing. Existing bcrypt `$2a$12$` hashes stay
valid — do **NOT** re-hash.

For an existing `admin_users` (single-domain) table, rename it to `users` (the
default table name) and add the missing columns (idempotent SQL — adjust to your
real columns):

```sql
ALTER TABLE admin_users RENAME TO users;
ALTER TABLE users RENAME COLUMN password TO password_hash;
ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified timestamptz;
ALTER TABLE users ADD COLUMN IF NOT EXISTS image text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS role text NOT NULL DEFAULT 'admin';
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE users ADD COLUMN IF NOT EXISTS disabled_at timestamptz;
ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();
```

Canonical columns authkit requires: `id (uuid pk)`, `name text null`,
`email text unique`, `email_verified timestamptz null`, `image text null`,
`password_hash text null`, `password_changed_at timestamptz`, `role text` (no DB
default — the service always sets it), `disabled_at timestamptz null`, the
two-factor columns (`two_factor_secret`, `two_factor_recovery_codes`,
`two_factor_confirmed_at`, `two_factor_last_used_at` — all nullable, added by the
migrations if absent), `created_at`, `updated_at`. **Extra app columns are
tolerated.** Then `./artisan migrate` (idempotent migrations create `audit_logs`,
`auth_remember_tokens`, `auth_sessions` and add any missing user columns).

### B4. Remove the app's old auth code

Delete (or stop wiring) the now-duplicated code and its references:

- the app's auth + user/admin **controllers**, the auth/admin **service** + its
  repository, the session/auth **middleware** (`AdminAuth` etc.), the app's
  `User`/`AdminUser` **model**, the session-regen helper, and the bootstrap
  `create-admin` command (use `auth:create-user`).
- remove the app's auth/user **routes** — `RegisterAll` mounts the package's own.
- domain handlers that read the authenticated user id from context can use
  `authkitroutes.AuthUserID(ctx)` (or `helpers.AuthUserID(ctx)`) — keep that
  consistent if domain code depends on it.

Then add the one-line `authkitroutes.RegisterAll(facades.Route())` (see Path A).
Do the SQL reshape in B3 **before** the first `migrate`.

## Path C — multiple user domains (multi-guard)

When the app has **two separate user tables** (the case the old skill called the
`admin_users → users` reshape and forced you to merge into one table), v0.2.0 lets
you keep both tables as-is. Declare **one guard per domain**; each guard points at
its existing table. **Do not merge the tables.**

### C1. Declare the guards in `config/authkit.go`

Root-level `authkit.*` keys apply to all guards as defaults; each guard overrides
what it needs. Each guard's `prefix` and `users_table` are required; the
audit/remember/sessions tables and remember cookie default to `<name>_*` /
`authkit_<name>_remember` but you can point them at your own:

```go
config.Add("authkit", map[string]any{
	"min_password_length": 8,
	"features": map[string]any{"user_management": true, "two_factor": true, /* ... */},
	"roles":   []string{"admin", "user"},

	"guards": map[string]any{
		// Staff portal, backed by the existing admin_users table.
		"admin": map[string]any{
			"prefix":      "/api/admin/v1",
			"users_table": "admin_users",
		},
		// Customer portal, backed by the existing accounts table; longer
		// passwords, 2FA off.
		"client": map[string]any{
			"prefix":              "/api/v1",
			"users_table":         "accounts",
			"min_password_length": 12,
			"features":            map[string]any{"two_factor": false},
		},
	},
})
```

Per guard you may also override `audit_table`, `remember_tokens_table`,
`sessions_table`, `remember_cookie_name`, `roles`, `user_management_roles`,
`rate_limit.*`, `two_factor.*`, `remember.*`. (Two guards on one origin must have
distinct remember cookie names — the default `authkit_<name>_remember` already
differs per guard.)

### C2. Own the tables: opt out of auto-migrations, register them yourself

Because the host already owns `admin_users` and `accounts` (with their own app
columns), set `authkit.register_migrations = false` and register
`migrations.ForTables(...)` per table yourself, so each existing table is reshaped
to carry authkit's required columns (idempotent — only missing columns are added):

```go
// config/authkit.go
"register_migrations": false,
```

```go
// bootstrap/migrations.go
import "github.com/freshost/goravel-authkit/migrations"

func Migrations() []schema.Migration {
	out := []schema.Migration{ /* your own app migrations */ }
	out = append(out, migrations.ForTables(migrations.MigrationConfig{UsersTable: "admin_users"})...)
	out = append(out, migrations.ForTables(migrations.MigrationConfig{UsersTable: "accounts"})...)
	return out
}
```

Each `ForTables(...)` set has table-derived signatures (`authkit_<table>_<step>`),
so the two domains never collide. The required columns are the same canonical set
as [B3](#b3-reshape-the-existing-table-to-the-canonical-users-shape): authkit's Up
steps add `password_hash`, `password_changed_at`, `role`, `disabled_at`,
`email_verified` and the `two_factor_*` columns where missing; your extra app
columns are tolerated. (Leave `register_guards = true` — the Goravel guards are
auto-registered fine; it's the *tables* you own.)

### C3. Mount routes + remove old code

`authkitroutes.RegisterAll(facades.Route())` mounts **both** guards (admin at
`/api/admin/v1/auth/*`, client at `/api/v1/auth/*`). Remove the app's old auth
controllers/services/middleware/routes for **both** domains, as in
[B4](#b4-remove-the-apps-old-auth-code).

### C4. Protect the host's own routes with a guard

To gate your own (non-authkit) routes behind a guard, use the middleware chain
helpers and read the current user inside the handler:

```go
import authkitroutes "github.com/freshost/goravel-authkit/routes"

facades.Route().Prefix("/api/v1/portal").
	Middleware(authkitroutes.Protect("client")...). // or ProtectRole("client", "admin", ...)
	Group(func(r route.Router) {
		r.Get("/whoami", func(ctx http.Context) http.Response {
			return ctx.Response().Success().Json(http.Json{
				"userId": authkitroutes.AuthUserID(ctx).String(),
			})
		})
	})
```

`Protect(guard)` = session + authenticate against that guard's table;
`ProtectRole(guard, roles…)` adds a role gate; `AuthUserID(ctx)` returns the
current user's `uuid.UUID` (or `uuid.Nil`).

### C5. Seed users into a non-default table

`auth:create-user` only writes the **default `users`** table, so for a guard on
another table create the user programmatically (a seeder or a small command):

```go
import "github.com/freshost/goravel-authkit"

kit := authkit.New(authkit.Config{Guard: "client", UsersTable: "accounts"})
_, err := kit.CreateUser(ctx, "customer@example.com", "Jane", "change-me-12ch", "user")
```

`authkit.New(authkit.Config{Guard, UsersTable, MinPasswordLength, Roles, …})`
drives auth / user-management / two-factor against the table you name.

## Step S — regenerate the API SDK

As of v0.2.0 the controllers carry **no Swagger/`@`-annotations** (dynamic
per-guard mounting can't be expressed in static annotations), so `swag` will
**not** pick up authkit's endpoints — they will simply be absent from your
generated OpenAPI/SDK. That's expected: the frontend talks to authkit through the
hand-written `@freshost/authkit-ui` (Step F), which carries its own typed client.

So for authkit itself there is nothing to regenerate. If your `swag` run errors on
the missing endpoints, **exclude** the authkit package from the scan or document
its endpoints separately (see `docs/api-reference.md` for the route shapes). Your
own app's `make swagger` + `make generate-api` is otherwise unchanged.

## Step F — frontend (`@freshost/authkit-ui`)

The companion package `@freshost/authkit-ui` (hand-written, unchanged in this
release) replaces the app's hand-rolled login / account / 2FA / user-management
UI. It talks to the backend through its **own typed client** over the stable
authkit routes — it does **not** depend on the app's generated SDK, so adopting it
is independent of Step S. Read its README for the full API.

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
   Pass `baseURL` (the guard's prefix, e.g. `/api/v1`), `branding`, and `routes`.
   For a multi-guard app, run one provider per portal pointed at each guard's
   prefix.
3. **Swap the pages**: replace the app's `LoginPage` / account / admin-users
   pages and `useAuth`/`useAdminUsers` hooks with the package's `LoginPage`,
   `AuthGuard`, `AccountPage`/`ChangePasswordModal`, `UsersPage`, and the 2FA
   components (`TwoFactorSetup`, `DisableTwoFactor`, `RecoveryCodes`). Delete the
   old toast-coupled auth hooks; the package's hooks toast via your adapter.
4. **Keep the app's `QueryClient` defaults** — the package sets only per-query
   options. Don't add global `staleTime`/`retry` for it.

## Step V — verify

```bash
cd backend && go build ./... && go test ./...
./artisan migrate
./artisan auth:create-user --email=admin@example.com --password=...   # default users table
```

Then run the app and verify (read-only where the app warns about live writes).
Endpoints are under each guard's prefix (e.g. `/api/v1/auth/*`):

1. **Login** with the seeded admin → 200, session cookie set.
2. **GET `/auth/me`** → the user.
3. **Change password** (`PUT /auth/password`) → other sessions get
   `401 session_expired`, this one stays.
4. **User CRUD** (if enabled) → list/create/update/delete; last-admin +
   self-delete guards fire.
5. Wrong password / unknown email → identical `401 invalid_credentials`.
6. **Existing user still logs in** with the old password (Path B/C reshape).
7. **Multi-guard** (Path C): each guard's prefix works independently; a guard with
   `two_factor` off has no `/auth/two-factor*` routes; a protected host route
   (`Protect`) rejects an unauthenticated request and returns the user id once
   logged in.

## Common pitfalls

- **Tried to overwrite `config/auth.go`** → there's nothing to overwrite anymore.
  The provider auto-registers the guard(s); a hand-written guard of the same name
  still wins. Only own `config/auth.go` if you set `register_guards = false`.
- **Merged two user tables into one** → unnecessary in v0.2.0. Declare two guards
  (Path C), each pointing at its existing table.
- **User columns missing after migrate on a host-owned table** → you set
  `register_migrations = false` but didn't register `migrations.ForTables(...)`
  per table, or reshaped too late. Register per table and reshape **before** the
  first `migrate` (migrations are idempotent and add only missing columns).
- **Seeding a non-default table with `auth:create-user`** → that command only
  writes `users`. Use `authkit.New(authkit.Config{UsersTable: ...}).CreateUser`.
- **Login 500 on hash** → `config/hashing.go` not bcrypt cost 12.
- **`swag` errors / authkit endpoints not in the SDK** → expected: the package
  ships no annotations. Exclude it from the scan; the FE uses `@freshost/authkit-ui`.
- **Rate-limit/audit IP wrong behind proxy** → set `http.trusted_proxies`.
- **Two guards overwriting each other's remember cookie** → give each a distinct
  `remember_cookie_name` (the `authkit_<name>_remember` default already differs).
