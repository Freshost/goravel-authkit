# Architecture

`goravel-authkit` is a layered, app-agnostic Goravel package. It uses **only** the
upstream `github.com/goravel/framework/facades` (never app-local facade
wrappers), so it drops into any Goravel app regardless of that app's DI style.

## Guards (multi-instance)

As of v0.2.0 the package is **multi-guard**. A *guard* is one fully independent
authentication domain: its own route prefix, user table, Goravel session guard,
audit/remember/session tables, remember cookie, and feature set. An app declares
N guards under `authkit.guards`; a single-domain app is just the N=1 case and
keeps working unchanged. The mechanics that make a guard self-contained are:

- **Table-aware repositories.** Each repository is bound to a concrete table at
  construction (`repositories.New*WithTable(table)`) and applies it per query with
  GORM's `.Table(name)` — the idiomatic way to override a model's static table,
  since a `Tabler` `TableName()` result is cached and can't vary per instance.
  `Options` (and `migrations.MigrationConfig`) carry `UsersTable`, `AuditTable`,
  `RememberTokensTable`, `SessionsTable`.
- **Repo-based user loading.** `middleware.Authenticated` / `RequireRole`,
  `AuthController.Me` / `Logout`, and the remember middleware load the user
  through the table-aware repository, keyed by the session's `auth_<guard>_id`
  (read via `helpers.GuardUserID`). The Goravel guard is used **purely** as a
  per-guard session-id store (`Login` / `LoginUsingID` / `ID` / `Logout` /
  `Check`); the custom Goravel user provider was removed. This is what lets each
  guard resolve its own table without a per-guard model provider.
- **Per-guard session keys.** authkit's session bookkeeping is namespaced by
  guard — `helpers.PasswordChangedAtKey` / `TwoFactorUserIDKey` /
  `RememberIntentKey` produce `authkit_<guard>_*`. One shared session cookie thus
  carries multiple guards without collision (mirroring Goravel's own
  `auth_<guard>_id`).
- **Per-instance rate limiter.** `RateLimitAuth` builds its own limiter per call
  (was a package global), so two guards never share one IP-keyed bucket.
- **Per-guard remember cookie.** `Options.RememberCookieName`
  (default `authkit_<guard>_remember`) so two guards on one origin don't overwrite
  each other's persistent login.

## Layers

```
HTTP request
  └─ middleware/        Authenticated (guard session-id + password_changed_at),
  │                     RememberLogin, RateLimitAuth, RequireRole, TrackSession
  └─ http/controllers/  AuthController, UsersController, … — bind, map sentinel errors → {error,message}
        └─ services/    Auth, Users, Audit, TwoFactor, Remember, Sessions — validation + business rules + sentinel errors
              └─ repositories/  Users, Audit, … — table-aware GORM data access (interface seam for tests)
                    └─ models/   User, AuditLog (each repo holds its own `table`, applied via .Table(name))
```

- **Controllers** are thin: bind the request, call a service, map sentinel errors
  to the `{"error","message"}` envelope with `net/http` status constants. They
  carry **no** Swagger annotations (see below).
- **Services** own validation and business rules and return sentinel errors
  (`ErrInvalidCredentials`, `ErrValidation`, `ErrNotFound`, `ErrAlreadyExists`,
  `ErrLastAdmin`, …). They take `context.Context` first and never touch the HTTP
  session — establishing the session is the controller's job.
- **Repositories** are the data-access seam. Services depend on the
  `UsersRepository` / `AuditRepository` interfaces, so they unit-test against an
  in-memory fake with no framework boot. The ORM implementations use
  `facades.Orm()` and `.Table(r.table)`.
- **Hashing** is abstracted behind a `Hasher` interface (`FacadeHasher` wraps
  `facades.Hash()`), again for testability.

## The canonical User model

The package **owns** the `User` struct and its column shape. Each guard's users
live in that guard's own table (default `users`, or `<guard>_users` for a named
guard, or any configured name) — the struct is the same across every guard, only
the table name varies (applied per query via `.Table(name)`). There is no
field-level extensibility mechanism: every adopting app shares the exact shape. It is
Auth.js-shaped (nullable `name`/`image`/`email_verified`, nullable
`password_hash` for a future OAuth flow), with `password_changed_at` for session
invalidation and a `role` string (used by the optional `RequireRole`).

The package follows the Goravel
[package-development](https://www.goravel.dev/digging-deeper/package-development.html)
model: registering the ServiceProvider plus one route-registration line is the
whole integration.

- **ServiceProvider** (`authkit.ServiceProvider`) does its wiring in `Boot`,
  iterating the guards from config (`routes.GuardOptions()`):
  - **Auto-registers Goravel session guards.** For each declared guard it adds a
    `session`-driver guard over a single shared `authkit_orm` provider — but
    never clobbers a guard the host already defined (don't-clobber: it only sets a
    guard whose driver is unset, and only sets `auth.defaults.guard` when blank).
    So a fresh app needs no `config/auth.go`, while an existing app's hand-written
    guards still win. Opt out wholesale with `authkit.register_guards = false`.
  - **Auto-registers migrations.** For each guard it registers
    `migrations.ForTables(MigrationConfig{...})` against that guard's tables. Opt
    out with `authkit.register_migrations = false` to register `ForTables`
    yourself.
  - Registers the `auth:create-user` and `auth:prune-remember-tokens` commands
    (`app.Commands(...)`), binds the `facades.Authkit()` service, and exposes the
    config for `vendor:publish` (`app.Publishes(...)`).
  - It declares its framework dependencies via `Relationship()` (Config, Orm,
    Hash, Auth, Crypt, Schema, Route) so it boots after them.
- **Routes are NOT mounted by the provider.** Goravel rebuilds the HTTP engine
  when global middleware is set — which happens *after* providers boot — so any
  routes a provider registers in `Boot` are discarded. Instead the app mounts
  them from its own routing callback with one line:

  ```go
  authkitroutes "github.com/freshost/goravel-authkit/routes"
  // inside foundation.Setup().WithRouting(func(){ ... })
  authkitroutes.RegisterAll(facades.Route())
  ```

  `RegisterAll` iterates the same `GuardOptions()` list and mounts every guard's
  routes under its own prefix. The app must also enable session middleware
  globally (the package is cookie-based).
- **`setup/setup.go`** implements `package:install`: it registers the provider
  (`modify.RegisterProvider`), writes `config/authkit.go`
  (`modify.File().Overwrite()`), and injects `bcrypt rounds: 12` into
  `config/hashing.go`. (The Goravel guard is auto-registered at boot rather than
  written into `config/auth.go`, so a single-guard app needs no `config/auth.go`
  at all.)
- **Migrations** are code-based, parameterised by table name
  (`migrations.ForTables`), with table-derived signatures
  (`authkit_<table>_<step>`). Every `Up` is idempotent: a create skips when the
  table already exists, an alter skips when the column already exists.
- **Config** is optional at runtime (safe fallbacks everywhere), but
  `package:install` writes `config/authkit.go` so apps have a tunable file.

## Layout

The repository follows the official
[goravel/example-package](https://github.com/goravel/example-package) layout:
`service_provider.go` + `setup/` at the root, with the implementation in
root subpackages (`models`, `repositories`, `services`, `http`, `helpers`,
`routes`, `migrations`, `commands`). An app registers `authkit.ServiceProvider`
and calls `routes.RegisterAll` from its routing callback; it does not otherwise
import the subpackages — though a host that wants to guard its *own* routes
behind an authkit guard uses `routes.Protect` / `routes.ProtectRole` (see the
API reference).

## No Swagger / OpenAPI annotations

The package ships **no** Swagger/OpenAPI `@`-annotations on its controllers. The
dynamic, per-guard route mounting cannot be expressed in static annotations
(the same controller is mounted under each guard's prefix), so `swag` has nothing
to scan. The HTTP endpoints are stable and documented in the API reference, but a
host that wants them in its generated OpenAPI/SDK must use a route-/type-driven
generator (or exclude them from `swag`). The companion React `@freshost/authkit-ui`
package ships a hand-written typed client rather than depending on a per-app SDK.

## What is out of scope (frontend)

A Go package cannot ship React components into a pnpm workspace. The frontend
counterpart — login page, `useAuth` hooks, account/users pages — lives in the
separate `@freshost/authkit-ui` npm package, consuming the contract above.

## Roadmap (post-v1)

Self-registration, email verification, password reset by email (needs a mailer),
and RBAC (roles/permissions tables, per-resource grants — distinct from the
multi-*guard* isolation shipped in v0.2.0). The `RequireRole` hook and the
nullable `password_hash` are the seams left for these.
