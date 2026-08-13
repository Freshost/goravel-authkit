# Changelog

All notable changes to `goravel-authkit` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While the package is pre-1.0, minor versions may contain breaking changes.

## [Unreleased]

## [0.6.0] - 2026-08-13

### Added

- Server-side administrator sign-in filters for the user's current name or
  email, recorded IP address, and password or remember-cookie method.
- Ascending and descending timestamp sorting for the paginated administrator
  sign-in overview.

### Changed

- `GET {prefix}/auth/admin/logins` now accepts the optional `user`, `ip`,
  `method`, and `sort` query parameters. Invalid method and sort values return a
  validation error.

## [0.5.0] - 2026-08-13

### Added

- A server-paginated, per-guard administrator sign-in overview at
  `GET {prefix}/auth/admin/logins`, including the user's current name and email,
  authentication method, client IP, and timestamp. It is protected by the
  fail-closed user-management role gate and unavailable during impersonation.
- A per-guard `(action, created_at)` audit index migration for efficient sign-in
  history pagination on large audit tables.

## [0.4.0] - 2026-08-11

### Added

- Optional per-guard personal API tokens with mandatory expiration, configured
  scopes, one-time plaintext display, SHA-256 hashes at rest, session-only
  management endpoints, token-only/hybrid host middleware, pruning, audit events,
  and companion account UI.

### Security

- Email syntax is now validated in the service layer for user creation, user
  updates, profile updates, and direct authentication callers.
- State-changing Authkit routes now reject requests without a same-origin or
  explicitly trusted `Origin`/`Referer` by default.
- Authentication rate limits now combine atomic IP and account/user buckets.
  A host can register a distributed backend with `RegisterRateLimitStore`.

### Changed

- Replaced `rate_limit.attempts` with `ip_attempts`, `account_attempts`, and
  `password_attempts`; removed the old `RateLimitAuth` middleware contract.

## [0.3.0] - 2026-08-09

### Changed

- **Goravel 1.18 is now required.** Authkit's HTTP middleware implementations
  adopt Goravel 1.18's `Handle` / `Signature` interface. Consumer calls to the
  exported middleware factories are unchanged. Consumers that manually invoked a
  returned middleware value as a function must call `middleware.Handle(ctx)`;
  the package is no longer source-compatible with Goravel 1.17.

### Added

- **User impersonation ("login as user").** An authorized actor can switch into
  another user's session and back — within its own guard or across guards — so an
  admin can reproduce what a customer sees. Opt-in and fail-closed (off by default).
  - Endpoints (per guard, behind the session guard): `POST {prefix}/auth/impersonate`
    (`{ "guard": "<target guard>", "userId": "<uuid>" }`; `guard` empty = same guard)
    and `POST {prefix}/auth/impersonate/stop`.
  - **Universal:** same-guard and cross-guard. A cross-guard switch adds the target
    guard's session alongside the actor's (one shared cookie), so the actor stays
    signed in to its own guard and "stop" just drops the target session; a same-guard
    switch replaces the user and "stop" restores the original.
  - **Layered authorization** (fail-closed): a declarative config gate per actor
    guard — `authkit.guards.<g>.impersonation.{roles, target_guards, protected_roles}`
    plus the global `authkit.impersonation.enabled` — and an optional host hook
    `authkit.RegisterImpersonationPolicy` (the `authkit.Impersonator` interface over
    `authkit.Principal`) that runs only after the gate passes, so it can only tighten
    the decision. `target_guards` accepts `"*"`, specific guard names, or the actor's
    own guard for same-guard.
  - **Security:** audit entries (`auth.impersonation_started` / `_stopped`);
    session-id regeneration on switch and stop; **no remember cookie** is issued
    (impersonation is ephemeral); the target must exist and not be disabled;
    `protected_roles` blocks impersonating privileged targets; a
    reject-while-impersonating guard blocks password change, user management and
    nested impersonation during a switch; `/auth/me` exposes `impersonatedBy`
    (for a UI banner + exit) and `/auth/meta` exposes `features.impersonation`.
  - New `routes.Options` fields: `EnableImpersonation`, `ImpersonationRoles`,
    `ImpersonationTargetGuards`, `ImpersonationProtectedRoles`.

## [0.2.0] - 2026-06-24

Multi-guard (multi-instance) support: run several fully independent authentication
domains — each with its own user table, session guard, routes, cookies and feature
set — in one Goravel app, while a single-domain app keeps working unchanged.

### Added

- **Multi-guard configuration.** Declare auth domains under `authkit.guards` in
  `config/authkit.go`; each entry is a guard (its `prefix`, `users_table`, and
  optional overrides). `routes.RegisterAll(router)` mounts every declared guard
  (or the single default guard when none are declared).
- **Auto-wiring from config.** The ServiceProvider registers a Goravel session
  guard and the migrations for each declared guard automatically — so a fresh app
  needs no `config/auth.go` and no per-guard route/migration wiring. Opt out with
  `authkit.register_guards = false` / `authkit.register_migrations = false`.
- **Table-aware repositories.** `repositories.New*WithTable(table)` constructors;
  every query uses GORM `.Table(name)`. New `Options.UsersTable`, `AuditTable`,
  `RememberTokensTable`, `SessionsTable`.
- **Per-guard config overrides.** `min_password_length`, `features.*`, `roles`,
  `user_management_roles`, `rate_limit.*`, `two_factor.*` and `remember.*` may be
  set at the authkit root (apply to all guards) and overridden per guard.
- **Per-instance remember cookie.** `Options.RememberCookieName` (default
  `authkit_<guard>_remember`) so two guards on one origin don't overwrite each
  other's persistent login.
- **Programmatic instance API.** `authkit.New(authkit.Config{Guard, UsersTable, …})`
  drives auth/user-management/2FA against a specific table (for CLI/seeders).
- **Parameterised migrations.** `migrations.ForTables(MigrationConfig)` returns the
  migration set for arbitrary table names (table-derived signatures), for hosts
  that own their tables.
- **Guarding the host's own routes.** `routes.Protect(guard)` and
  `routes.ProtectRole(guard, roles…)` return the middleware chain that authenticates
  a host route behind a guard (the authkit equivalent of Laravel's `auth:guard`);
  `routes.AuthUserID(ctx)` reads the current user inside a protected handler.

### Changed

- **User loading no longer uses Goravel's user provider.** `Authenticated`,
  `RequireRole`, `Me`, `Logout` and the remember-me middleware now load the user
  through authkit's table-aware repository (keyed by the session's `auth_<guard>_id`).
  The Goravel guard is used purely as a per-guard session-id store, so each guard
  resolves its own table without a custom provider.
- **Session keys are namespaced per guard** (`authkit_<guard>_password_changed_at`,
  `…_two_factor_user_id`, `…_remember_intent`), so one shared session cookie carries
  multiple guards without collision (mirroring Goravel's own `auth_<guard>_id`).
- **Rate limiter is per-instance** (was a package global), so two guards never share
  one IP-keyed bucket.
- **Active-session tracking is keyed by a stable per-guard token** (stored in the
  session) instead of the Goravel session id. The id rotates on every login (for
  session-fixation protection); the token does not, so a guard's tracked session
  survives another guard's login on the same shared cookie.
- **Migrations unified.** Both single- and multi-guard mode register
  `ForTables(...)`; `Migrations()` is now `ForTables(MigrationConfig{})`.
- **Single-guard apps no longer require `config/auth.go`** — the guard is
  auto-registered (an existing hand-written guard still wins).

### Removed

- **All Swagger/OpenAPI `@`-annotations** from the controllers. The package ships no
  swagger definitions (dynamic per-guard mounting can't be expressed in static
  annotations). Document authkit's endpoints with a route-/type-driven generator, or
  exclude them from `swag` (the React `@freshost/authkit-ui` is hand-written).
- **The custom Goravel user provider** (`user_provider.go`), replaced by repo-based
  loading.
- The package-global rate limiter and the unused `ResetRateLimiters` test helper.

### Breaking changes & upgrade notes

- **Migration signatures changed** from `20260101_0000NN_*` to
  `authkit_<table>_<step>`. Every migration is idempotent (a create skips when the
  table exists, an alter skips when the column exists), so re-running is safe — but
  the framework's migrations table records the new signatures (old rows are left
  in place and harmless). A pristine install gets the new signatures only.
- **Middleware signatures changed:** `middleware.Authenticated(guard, usersRepo)`,
  `middleware.RequireRole(guard, usersRepo, roles…)`, `middleware.RememberLogin(guard,
  rememberCookieName, usersRepo, …)`. Apps that wired these by hand must pass the
  repo. The recommended path (`routes.RegisterAll` / `routes.Protect`) handles this.
- **Controllers carry no swagger annotations**, so hosts that relied on authkit
  endpoints appearing in their `swag`-generated OpenAPI/SDK no longer get them.

### Security

- Each guard is an isolated auth domain: separate user table, separate session key,
  separate remember cookie, separate rate-limit bucket. The session-cookie model
  (httpOnly, no tokens/localStorage) is unchanged.
- Active-session tracking is keyed by a stable per-guard token (not the Goravel
  session id, which rotates on every login for anti-fixation), so concurrent logins
  to several guards in one shared-cookie browser all keep working — the tracking row
  survives the rotation. For stronger isolation, run each portal on its own
  subdomain/origin (a distinct per-guard session cookie name/path is an optional knob
  for single-origin setups).

## [0.1.0]

- Initial release: session-based auth, user management, TOTP two-factor, audit log,
  remember-me, active-session tracking — single guard.

[Unreleased]: https://github.com/Freshost/goravel-authkit/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/Freshost/goravel-authkit/releases/tag/v0.6.0
[0.5.0]: https://github.com/Freshost/goravel-authkit/releases/tag/v0.5.0
[0.4.0]: https://github.com/Freshost/goravel-authkit/releases/tag/v0.4.0
[0.3.0]: https://github.com/Freshost/goravel-authkit/releases/tag/v0.3.0
[0.2.0]: https://github.com/Freshost/goravel-authkit/releases/tag/v0.2.0
[0.1.0]: https://github.com/Freshost/goravel-authkit/releases/tag/v0.1.0
