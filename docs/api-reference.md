# API Reference

Every package route lives under **`{prefix}/auth`** — a single owned namespace so
the package never collides with the host app's own routes (its `/meta`, `/users`,
…). The paths below are relative to that base. In a single-guard app the prefix is
`Options.Prefix` (default `/api/v1`). In a **multi-guard** app the *same* endpoint
set is mounted once **per guard**, each under its own guard's prefix
(e.g. `/api/v1/auth/login` for the `client` guard and `/api/admin/v1/auth/login`
for the `admin` guard). The endpoints themselves are unchanged from v0.1.

The `@ID` column is the operation id used by the React `@freshost/authkit-ui`
client. As of v0.2.0 the controllers carry **no** Swagger/OpenAPI annotations
(per-guard mounting can't be expressed statically), so these ids no longer flow
into a host's `swag`-generated SDK — they are documentation of the stable wire
contract. Auth endpoints other than login require the session cookie (guarded by
`Authenticated`, which loads the user from the guard's own table).

| Method | Path | `@ID` | Auth |
| --- | --- | --- | --- |
| GET | `/auth/meta` | `getAuthkitConfig` | public — role options + feature flags for the UI |

## Auth

| Method | Path | `@ID` | Auth | Success | Errors |
| --- | --- | --- | --- | --- | --- |
| POST | `/auth/login` | `login` | public (rate-limited) | `200` UserResponse | `400` `401` `429` `500` |
| POST | `/auth/logout` | `logout` | cookie | `200` MessageResponse | `401` |
| GET | `/auth/me` | `getMe` | cookie | `200` UserResponse | `401` |
| PUT | `/auth/me` | `updateProfile` | cookie | `200` UserResponse | `400` `401` `409` `500` |
| PUT | `/auth/password` | `changePassword` | cookie | `200` MessageResponse | `400` `401` `500` |
| GET | `/auth/logins` | `getLoginHistory` | cookie | `200` `[]LoginHistoryEntry` | `401` |

## Administrator sign-in overview (when `features.audit_log`)

Uses the same fail-closed roles as user management (`user_management_roles`,
default `admin`) and is unavailable during impersonation. Results contain only
successful password and remember-cookie sign-ins for the current guard.

| Method | Path | `@ID` | Auth | Success | Errors |
| --- | --- | --- | --- | --- | --- |
| GET | `/auth/admin/logins?page=1&perPage=20` | `listAdminLogins` | cookie + admin role | `200` AdminLoginPageResponse | `400` `401` `403` `500` |

`page` defaults to `1`; `perPage` defaults to `20` and is capped at `100`.

## Sessions (when `features.sessions`)

| Method | Path | `@ID` | Auth | Success | Errors |
| --- | --- | --- | --- | --- | --- |
| GET | `/auth/sessions` | `listSessions` | cookie | `200` `[]SessionResponse` | `401` |
| DELETE | `/auth/sessions` | `terminateOtherSessions` | cookie | `200` MessageResponse | `401` |
| DELETE | `/auth/sessions/{id}` | `terminateSession` | cookie | `200` MessageResponse | `400` `404` |

## Personal API tokens (when `features.api_tokens`)

Management is session-only and CSRF-protected. Creation additionally requires
the current password and a live TOTP code when the user has 2FA enabled. It is
blocked during impersonation. Plaintext is returned only by the create response.

| Method | Path | Auth | Success | Errors |
| --- | --- | --- | --- | --- |
| GET | `/auth/api-tokens` | cookie | `200` `[]APITokenResponse` | `401` |
| POST | `/auth/api-tokens` | cookie + password (+ TOTP) | `201` IssuedAPITokenResponse | `400` `401` `409` `429` |
| DELETE | `/auth/api-tokens/{id}` | cookie | `200` MessageResponse | `400` `404` |
| DELETE | `/auth/api-tokens` | cookie | `200` MessageResponse | `401` |

```jsonc
// expiresAt is mandatory RFC3339
{
  "name": "Deployment CLI",
  "expiresAt": "2026-09-10T23:59:59Z",
  "scopes": ["deployments:read", "deployments:write"],
  "password": "current-password",
  "twoFactorCode": "123456"
}

// 201 — token is shown once; list responses never contain it
{
  "id": "...", "name": "Deployment CLI", "scopes": ["deployments:read"],
  "expiresAt": "...", "lastUsedAt": null, "createdAt": "...",
  "token": "gak_<selector>.<validator>"
}
```

Host routes opt into bearer authentication with `routes.ProtectToken`, or accept
either a session or token with `routes.ProtectAny`. Send tokens as
`Authorization: Bearer <token>`.

> When the user has 2FA enabled, `login` returns `200 {"two_factor": true}`
> **without** establishing the session — the client must then call
> `two-factor-challenge`.

## Two-factor (when `EnableTwoFactor`)

| Method | Path | `@ID` | Auth | Success | Errors |
| --- | --- | --- | --- | --- | --- |
| POST | `/auth/two-factor-challenge` | `twoFactorChallenge` | pending session (rate-limited) | `200` UserResponse | `400` `401` `429` |
| POST | `/auth/two-factor` | `enableTwoFactor` | cookie | `200` TwoFactorEnrollmentResponse | `401` `409` |
| POST | `/auth/two-factor/confirm` | `confirmTwoFactor` | cookie | `200` RecoveryCodesResponse | `400` `401` |
| DELETE | `/auth/two-factor` | `disableTwoFactor` | cookie (+ password re-auth) | `200` MessageResponse | `400` `401` |
| GET | `/auth/two-factor/recovery-codes` | `getTwoFactorRecoveryCodes` | cookie | `200` RecoveryCodesStatusResponse (count only) | `401` |
| POST | `/auth/two-factor/recovery-codes` | `regenerateTwoFactorRecoveryCodes` | cookie | `200` RecoveryCodesResponse | `401` |

Enrollment flow: `enableTwoFactor` (get secret + otpauth URL → render QR) →
user scans → `confirmTwoFactor` with a code (activates, returns recovery codes).
Login flow with 2FA: `login` → `{two_factor:true}` → `twoFactorChallenge` with a
`code` **or** `recoveryCode`.

## Users (when `EnableUserManagement`)

| Method | Path | `@ID` | Success | Errors |
| --- | --- | --- | --- | --- |
| GET | `/auth/users` | `listUsers` | `200` `[]UserResponse` | `401` |
| POST | `/auth/users` | `createUser` | `201` UserResponse | `400` `409` |
| GET | `/auth/users/{id}` | `getUser` | `200` UserResponse | `404` |
| PUT | `/auth/users/{id}` | `updateUser` | `200` UserResponse | `400` `404` `409` |
| DELETE | `/auth/users/{id}` | `deleteUser` | `200` MessageResponse | `400` `404` `409` |
| POST | `/auth/users/{id}/password` | `setUserPassword` | `200` UserResponse | `400` `404` |

## Impersonation (when `EnableImpersonation`)

An authorized actor switches into another user's session — within its own guard or
across guards — and back. Both endpoints sit behind the session guard. See
[security](security.md) and [configuration](configuration.md#impersonation) for the
authorization gate.

| Method | Path | `@ID` | Auth | Success | Errors |
| --- | --- | --- | --- | --- | --- |
| POST | `/auth/impersonate` | `impersonate` | cookie | `200` UserResponse (the target, with `impersonatedBy`) | `400` `403` `404` `409` `500` |
| POST | `/auth/impersonate/stop` | `stopImpersonating` | cookie | `200` MessageResponse | `400` |

- **`impersonate`** establishes the target user's session. On success it returns the
  **target's** `UserResponse` with the `impersonatedBy` field populated (the actor's
  guard / id / email), so the UI can render a banner and an exit action. No remember
  cookie is issued — impersonation is ephemeral. `impersonate` is blocked while a
  switch is already active on this guard (`409 already_impersonating`) so it cannot
  nest.
- **`stop`** ends the switch on this guard. For a same-guard switch it restores the
  original actor; for a cross-guard switch it drops only the target session (the
  actor's own-guard session, a different key in the shared cookie, is untouched). It
  stays reachable from the impersonated session.

The reject-while-impersonating guard returns `403 impersonation_forbidden` on
`PUT /auth/password`, the `/auth/users*` endpoints and a nested
`POST /auth/impersonate` while a switch is active.

## Request bodies

```jsonc
// LoginRequest — `remember` is optional (default false)
{ "email": "admin@example.com", "password": "secret", "remember": true }

// UpdateProfileRequest — the user's own name + email
{ "email": "admin@example.com", "name": "Admin" }

// ChangePasswordRequest
{ "currentPassword": "secret", "newPassword": "new-secret" }

// CreateUserRequest
{ "email": "jane@example.com", "name": "Jane Admin", "password": "secret", "role": "admin" }

// UpdateUserRequest — `disabled` is optional (omit to leave unchanged)
{ "email": "jane@example.com", "name": "Jane Admin", "role": "admin", "disabled": false }

// SetPasswordRequest
{ "password": "new-secret" }

// TwoFactorChallengeRequest — supply exactly one
{ "code": "123456" }            // TOTP code
{ "recoveryCode": "ABCDE-FGHJK" } // or a recovery code

// TwoFactorConfirmRequest
{ "code": "123456" }

// TwoFactorDisableRequest — re-auth before disabling 2FA
{ "password": "secret" }

// ImpersonateRequest — `guard` is the target's guard (empty/omitted = the actor's
// own guard, i.e. same-guard); `userId` is the target user's uuid
{ "guard": "client", "userId": "3f2504e0-4f89-41d3-9a0c-0305e82c3301" }
```

## Response shapes

```jsonc
// UserResponse — never includes the password hash
{
  "id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
  "email": "admin@example.com",
  "name": "Admin",
  "role": "admin",
  "twoFactorEnabled": false,
  "disabled": false,
  "createdAt": "2026-01-01T00:00:00Z",
  // present ONLY while this user is being impersonated (a UI banner + exit cue)
  "impersonatedBy": { "guard": "admin", "id": "…", "email": "admin@example.com" }
}

// MetaResponse — GET /auth/meta (public; the UI reads roles/features from here)
{
  "roles": ["admin", "user"],
  "minPasswordLength": 8,
  "features": { "userManagement": true, "twoFactor": true, "auditLog": true, "sessions": true, "impersonation": false, "apiTokens": true },
  "apiTokens": { "allowedScopes": ["deployments:read"], "defaultLifetimeDays": 30, "maxLifetimeDays": 365, "maxPerUser": 20 }
}

// SessionResponse — one active session (secret session id never exposed)
{
  "id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
  "ip": "203.0.113.7",
  "userAgent": "Mozilla/5.0 ...",
  "current": true,
  "createdAt": "2026-01-01T00:00:00Z",
  "lastActiveAt": "2026-01-01T01:00:00Z"
}

// LoginHistoryEntry — a recent successful sign-in (action = auth.login | auth.login_remember)
{ "action": "auth.login", "ip": "203.0.113.7", "createdAt": "2026-01-01T00:00:00Z" }

// AdminLoginPageResponse — successful sign-ins across this guard
{
  "items": [{
    "id": "…", "userId": "…", "userName": "Admin", "userEmail": "admin@example.com",
    "action": "auth.login", "ip": "203.0.113.7", "createdAt": "2026-01-01T00:00:00Z"
  }],
  "page": 1, "perPage": 20, "total": 1, "totalPages": 1
}

// MessageResponse
{ "message": "Password changed" }

// TwoFactorRequiredResponse — login when 2FA is enabled
{ "two_factor": true }

// TwoFactorEnrollmentResponse
{ "secret": "JBSWY3DPEHPK3PXP", "otpauthUrl": "otpauth://totp/App:admin@example.com?secret=...&issuer=App" }

// RecoveryCodesResponse — shown ONCE, on confirm/regenerate (codes are stored hashed)
{ "recoveryCodes": ["ABCDE-FGHJK", "..."] }

// RecoveryCodesStatusResponse — GET recovery-codes returns only the unused count
{ "remaining": 6 }

// ErrorResponse — the standard error envelope
{ "error": "invalid_credentials", "message": "Invalid email or password" }
```

## Error codes

| HTTP | `error` | When |
| --- | --- | --- |
| 400 | `validation_error` | Bad body / invalid input |
| 400 | `wrong_password` | Change-password current password incorrect |
| 400 | `invalid_id` | Malformed UUID path param |
| 400 | `self_delete` | Deleting your own account |
| 400 | `self_disable` | Disabling your own account |
| 400 | `current_session` | Terminating the current session (use logout) |
| 401 | `session_terminated` | The session was signed out elsewhere |
| 403 | `account_disabled` | The account is locked (`disabled`) — login + sessions refused |
| 401 | `invalid_credentials` | Login failed (unknown email **or** wrong password — never distinguished) |
| 401 | `unauthorized` | Missing/invalid session |
| 401 | `session_expired` | Password changed elsewhere → other sessions invalidated |
| 401 | `invalid_token` | Missing, malformed, expired, revoked, or otherwise invalid bearer token |
| 403 | `forbidden` | `RequireRole` gate failed, or the impersonation gate denied the actor |
| 403 | `insufficient_scope` | Valid bearer token lacks a required route scope |
| 403 | `impersonation_forbidden` | Action blocked while impersonating (password change, user management, nested impersonation) |
| 403 | `csrf_failed` | Unsafe request has no same-origin or explicitly trusted Origin/Referer |
| 409 | `already_impersonating` | An impersonation is already active on this guard (no nesting) |
| 404 | `not_found` | User does not exist (or the impersonation target is unknown) |
| 409 | `already_exists` | Email already taken |
| 409 | `last_admin` | Deleting the last user |
| 409 | `token_limit` | User reached the configured active-token maximum |
| 429 | `rate_limited` | An IP, account, 2FA-user, or password-user bucket is exhausted |
| 503 | `rate_limiter_unavailable` | The configured rate-limit store failed; authentication fails closed |
| 503 | `authentication_unavailable` | Token/user lookup failed; bearer authentication fails closed |

## Behavioural notes

- **Login** establishes an httpOnly session cookie, regenerates the session id
  (anti-fixation), and stamps `password_changed_at` into the session.
- **Change-password** invalidates **every other** session for that user (their
  stamp no longer matches the DB); the calling session is re-stamped and stays
  in.
- **Delete** refuses to remove the last user (`last_admin`) and refuses
  self-delete (`self_delete`).
- Failed logins are recorded to `audit_logs` (`auth.login_failed`) when audit is
  enabled.
- **Remember me** (when `features.remember_me`, default on): `login` with
  `"remember": true` issues a long-lived, http-only `authkit_remember` cookie
  (selector-validator token in `auth_remember_tokens`, default 30-day sliding
  expiry). When the short session has expired, a guarded-route middleware
  silently re-establishes it from this cookie and **rotates** the validator on
  every use. The just-superseded validator is honoured for a short grace window
  (60s) so concurrent requests aren't mistaken for theft; a validator that is
  stale beyond that (or simply wrong) for a known selector is treated as theft
  and revokes the user's whole token family. With 2FA the cookie is issued only
  after the challenge completes. Logout revokes this device's token; a password
  change (and disabling the account) revokes **all** of the user's remember
  tokens. Expired rows are pruned lazily on access and by the
  `auth:prune-remember-tokens` command (schedule it daily).
- **Disabled accounts**: setting `disabled` on a user (`PUT /auth/users/{id}`)
  locks the account — login returns `403 account_disabled`, and any live session
  or remember cookie is rejected on its next request. You cannot disable your own
  account (`400 self_disable`).
- **Active sessions** (when `features.sessions`): each login is tracked in
  `auth_sessions` (session id, IP, user-agent, last-active). `GET /auth/logins`
  returns the user's recent successful sign-ins; `GET /auth/sessions` lists their
  active sessions (the current one flagged). Deleting a session row terminates
  it — the `TrackSession` middleware rejects the next request from a session with
  no row (`401 session_terminated`). You can't terminate the current session via
  the API (`400 current_session`) — use logout. A password change drops all other
  session rows; stale rows are pruned by `auth:prune-remember-tokens`.
- **Impersonation** (when `EnableImpersonation`): `POST /auth/impersonate`
  establishes the target's session and regenerates the session id; **no remember
  cookie** is issued (the switch is ephemeral and not restorable from a persistent
  cookie). The target must exist (`404 not_found`) and not be disabled
  (`403 account_disabled`), and must not hold a `protected_role`
  (`403 forbidden`). While a switch is active, `GET /auth/me` returns the
  impersonated user with an `impersonatedBy` object ({ guard, id, email }), and the
  password-change, user-management and nested-impersonate routes return
  `403 impersonation_forbidden`. `GET /auth/meta` reports
  `features.impersonation`. Both the start and stop are audited
  (`auth.impersonation_started` / `auth.impersonation_stopped`).

## Go API (mounting & host integration)

The HTTP surface above is wired by these exported Go entry points. Import
`authkitroutes "github.com/freshost/goravel-authkit/routes"`.

### Mounting routes

```go
// Mount every declared guard (authkit.guards), or the single default guard when
// none are declared. This is the one line an app adds to its routing callback.
authkitroutes.RegisterAll(facades.Route())

// Mount one guard explicitly from a built Options.
authkitroutes.Register(facades.Route(), opts)
```

- **`RegisterAll(router route.Router)`** iterates `GuardOptions()` and calls
  `Register` for each. Single- and multi-guard apps use the same one-liner.
- **`Register(router route.Router, opts Options)`** wires the services +
  controllers and mounts the `{opts.Prefix}/auth/*` routes. Zero-valued `Options`
  fields fall back to `DefaultOptions`, so `Register(router, Options{})` is safe.
- **`OptionsFromConfig() Options`** builds `Options` from the top-level
  `authkit.*` config (the single-guard base).
- **`OptionsForGuard(name string) Options`** builds the `Options` for one declared
  guard: starts from `OptionsFromConfig()`, applies the guard's overrides, and
  derives table names and the remember cookie from the guard name when unset
  (`<name>_users`, `<name>_audit_logs`, `<name>_remember_tokens`,
  `<name>_auth_sessions`, `authkit_<name>_remember`).
- **`GuardOptions() []Options`** is the resolved list both `RegisterAll` and the
  ServiceProvider iterate — one entry per `authkit.guards` child, or a single
  `OptionsFromConfig()` entry when none are declared.

### `Options` fields

`Options` configures one guard's routes and controller behaviour:

| Field | Purpose |
| --- | --- |
| `Prefix` | Route prefix (e.g. `/api/v1`); routes mount under `{Prefix}/auth`. |
| `Guard` | Goravel auth guard name backing the session (e.g. `admin`). |
| `MinPasswordLength` | Minimum accepted new-password length. |
| `RateLimitIPAttempts` / `RateLimitAccountAttempts` | Combined IP and account limits for login/challenge. |
| `RateLimitPasswordAttempts` / `RateLimitWindow` | Per-user password limit and shared window. |
| `RateLimitStore` | Optional atomic backend; otherwise the process-local memory store is used. |
| `EnableCSRF` / `TrustedOrigins` | Fail-closed request-origin verification and exact cross-origin allowlist. |
| `EnableUserManagement` | Register the `/users` CRUD endpoints. |
| `EnableAuditLog` | Wire the audit service into the controllers. |
| `UserManagementRoles` | Roles allowed at `/users` (fail-closed default `["admin"]`). |
| `Roles` | Accepted role values on create/update (empty = any). |
| `EnableTwoFactor` / `TwoFactorIssuer` / `RecoveryCodeCount` | TOTP two-factor. |
| `EnableRememberMe` / `RememberLifetime` | Persistent remember-me login. |
| `EnableSessions` / `SessionActiveWindow` | Active-session tracking + endpoints. |
| `EnableAPITokens` / token policy fields | Enable management and configure allowed scopes, expiry, maximum active tokens, and password-change revocation. |
| `UsersTable` / `AuditTable` / `RememberTokensTable` / `SessionsTable` / `APITokensTable` | Bind the repositories to per-guard tables. |
| `RememberCookieName` | This guard's remember cookie (empty → `authkit_remember`). Two guards on one origin must differ. |
| `EnableImpersonation` | Mount the impersonation endpoints + the reject-while-impersonating guards (off by default). |
| `ImpersonationRoles` | The actor must hold one of these roles to impersonate (empty = any authenticated user in this guard). |
| `ImpersonationTargetGuards` | Guards this guard's actors may impersonate into (`"*"` = any; include this guard's own name for same-guard; empty = cannot impersonate). |
| `ImpersonationProtectedRoles` | Target users holding one of these roles can never be impersonated. |

### Impersonation policy hook

The config gate (`ImpersonationRoles` / `ImpersonationTargetGuards` /
`ImpersonationProtectedRoles`) decides authorization declaratively. For finer rules
a config table can't express, register a host hook — it runs **only after** the
config gate has passed, so it can only tighten the decision:

```go
import "github.com/freshost/goravel-authkit"

type myPolicy struct{}

func (myPolicy) CanImpersonate(ctx context.Context, actor authkit.Principal, targetGuard string, target authkit.Principal) (bool, error) {
    return actor.Guard == "admin" && target.Role != "owner", nil // example
}

// Once at boot:
authkit.RegisterImpersonationPolicy(myPolicy{})
```

- **`authkit.RegisterImpersonationPolicy(p authkit.Impersonator)`** registers the
  hook process-wide (call once at boot). When none is registered, the config gate
  alone decides.
- **`authkit.Impersonator`** is the one-method interface
  `CanImpersonate(ctx, actor, targetGuard, target) (bool, error)` — return `false`
  to deny.
- **`authkit.Principal`** identifies one party in the decision:
  `{ Guard string; UserID uuid.UUID; Email string; Role string }`.

### Rate-limit store

Multi-instance hosts register one shared atomic backend before route mounting:

```go
type sharedLimiter struct { /* Redis client */ }

func (store *sharedLimiter) Hit(ctx context.Context, key string, limit int, window time.Duration) (authkit.RateLimitResult, error) {
    // Atomically consume one attempt and apply/retain the bucket expiry.
}

authkit.RegisterRateLimitStore(&sharedLimiter{})
```

`Hit` must be atomic across processes. Authkit supplies already namespaced and
SHA-256-hashed keys, so the backend never receives raw email, IP, or user ID.
Backend errors fail closed with `503 rate_limiter_unavailable`.

### Guarding the host's own routes

```go
// Authenticate the host's routes behind an authkit guard (the authkit
// equivalent of Laravel's auth:<guard>).
facades.Route().Prefix("/api/v1").
    Middleware(authkitroutes.Protect("client")...).
    Group(func(r route.Router) {
        r.Get("/invoices", invoices.Index) // requires a logged-in "client" user
    })
```

- **`Protect(guard string) []http.Middleware`** returns `StartSession` + CSRF
  origin verification (when enabled) + `Authenticated(guard, repo)` (the repo is
  bound to that guard's user table).
- **`ProtectRole(guard string, roles ...string) []http.Middleware`** is `Protect`
  plus a `RequireRole` gate (no roles → behaves like `Protect`).
- **`AuthUserID(ctx http.Context) uuid.UUID`** reads the current user id inside a
  protected handler (or `uuid.Nil`).

### Programmatic instance API

`authkit.New` drives auth / user-management / 2FA against a specific table
(for CLI tools, seeders, custom flows) without going through HTTP:

```go
client := authkit.New(authkit.Config{Guard: "client", UsersTable: "accounts"})
admin  := authkit.New(authkit.Config{Guard: "admin", UsersTable: "admin_users"})
u, err := admin.CreateUser(ctx, email, name, password, "admin")
```

`authkit.Config` fields (all optional; the zero value reproduces the
single-instance defaults): `Guard`, `UsersTable`, `MinPasswordLength`,
`TwoFactorIssuer`, `RecoveryCodeCount`, `Roles`, `UserManagementRoles`. The
returned `*Authkit` exposes `Authenticate`, `CreateUser`, `GetUser`, `ListUsers`,
`SetPassword`, `ChangePassword`, `DeleteUser`, `EnableTwoFactor`,
`ConfirmTwoFactor`, `VerifyTwoFactor`, `DisableTwoFactor`. The default instance
is also resolvable via `facades.Authkit()`.

### Migrations & repositories

- **`migrations.ForTables(cfg migrations.MigrationConfig) []schema.Migration`**
  returns the migration set for arbitrary table names, with table-derived
  signatures (`authkit_<table>_<step>`) so a host can register one set per user
  domain without collisions. `MigrationConfig` fields: `UsersTable`, `AuditTable`,
  `RememberTokensTable`, `SessionsTable` (empty → package defaults).
  `migrations.Migrations()` is `ForTables(MigrationConfig{})`. The ServiceProvider
  self-registers these per guard unless `authkit.register_migrations = false`.
- **`repositories.New*WithTable(table string)`** construct table-bound
  repositories (`NewUsersWithTable`, `NewAuditWithTable`,
  `NewRememberWithTable`, `NewSessionsWithTable`); an empty name falls back to the
  package default table. The bare `New*()` constructors use the default tables.
