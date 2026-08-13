# Security model

`goravel-authkit` uses session-cookie authentication for browsers and optional
opaque personal API tokens for non-browser clients. This document states the
guarantees, the operator responsibilities, and the known limitations.

## Per-guard isolation (multi-guard)

A guard is an **isolated** authentication domain. When an app runs several guards
(under `authkit.guards`), each is separated from the others by:

- a **separate user table** (resolved per query via GORM `.Table(name)`),
- a **separate session key** — Goravel's `auth_<guard>_id` plus authkit's
  per-guard bookkeeping (`authkit_<guard>_password_changed_at`,
  `…_two_factor_user_id`, `…_remember_intent`), so one shared session cookie
  carries multiple guards without collision,
- a **separate remember cookie** (`authkit_<guard>_remember` by default), so two
  guards on one origin don't overwrite each other's persistent login,
- a **separate API-token table** (`<guard>_api_tokens` by default),
- **namespaced rate-limit buckets** — each guard includes its name in every IP,
  account, 2FA-user, and password-user bucket, so attempts never cross guards
  even when they share one backend.

The user record is loaded from the guard's own table through authkit's
table-aware repository (keyed by the session's `auth_<guard>_id`); the Goravel
guard is only a per-guard session-id store. **Table names come from config**
(`authkit.guards.<name>.users_table`, etc.) — they are developer-controlled, not
user input, and are applied via GORM `.Table()`, so they are not an injection
vector. The browser session model remains httpOnly and never stores API tokens
in localStorage.

The auto-registered Goravel guard uses a `session` driver over a shared
`authkit_orm` provider and **never clobbers** a guard the host has already
defined (it only fills in an unset guard).

## Personal API tokens

API tokens are off by default. When enabled, Authkit issues opaque
`gak_<selector>.<validator>` credentials with mandatory expiry:

- Only the selector and SHA-256 validator hash are persisted; plaintext is shown
  once at creation and cannot be recovered.
- Creation/list/revocation endpoints accept session authentication only, retain
  CSRF checks, and creation requires the current password plus TOTP when enabled.
  All management is rejected during impersonation.
- Allowed scopes are configured per guard. Required middleware scopes only
  restrict a token; they never grant permissions beyond the live user's role and
  the host application's normal resource authorization.
- Every request loads the live owner. Deleted or disabled owners are denied.
  Password changes/resets and disabling/deleting a user revoke all tokens by
  default.
- `ProtectToken` is stateless. `ProtectAny` prefers any supplied Authorization
  header and never falls back to a session after an invalid token. Browser/session
  requests still receive CSRF protection.
- Schedule `auth:prune-api-tokens` daily to remove tokens expired or revoked more
  than 30 days ago. Never put bearer tokens in URLs or logs; use TLS.

## What the package guarantees

- **Password hashing** via the Goravel Hash facade (bcrypt). Hashes are never
  serialized (`json:"-"`) and never logged.
- **No credential enumeration on login.** Unknown-email and wrong-password
  return the identical `401 invalid_credentials`. The unknown-email path runs a
  real bcrypt comparison against a valid dummy hash so response timing does not
  reveal whether an email exists.
- **Session-fixation protection.** The session id is regenerated on login and
  the cookie re-emitted.
- **Multi-session invalidation on password change.** Each session stores the
  `password_changed_at` captured at login (under the per-guard key
  `authkit_<guard>_password_changed_at`); the `Authenticated` middleware compares
  it to the live DB value on every request. A password change bumps the DB value,
  so every *other* session is rejected (`401 session_expired`) on its next
  request. The session that changed the password is re-stamped and stays in.
- **Atomic multi-dimensional rate-limiting.** Login and 2FA must pass both an IP
  bucket (default 20/min) and a hash-keyed account/user bucket (default 5/min).
  Change-password must pass IP and authenticated-user buckets. Bucket identifiers
  are SHA-256 hashed before reaching the store. The default atomic sliding-window
  store is process-local; hosts can register a distributed implementation through
  `authkit.RegisterRateLimitStore`.
- **CSRF origin verification.** Every state-changing Authkit endpoint, plus host
  routes using `routes.Protect` / `ProtectRole`, fails
  closed unless `Origin` or `Referer` matches the request host or an exact
  `authkit.csrf.trusted_origins` entry. Requests without either header are
  accepted only with `Sec-Fetch-Site: same-origin`. Non-browser clients must
  identify their origin too.
- **`/users` is admin-gated by default (fail-closed).** The user-management
  endpoints (read and write) are always mounted behind a `RequireRole` check;
  `authkit.user_management_roles` defaults to `["admin"]`. A non-admin gets 403.
- **New users default to the least-privileged role.** A create with no explicit
  role is assigned a non-management role (the first configured non-admin role,
  else `"user"`) — it can never silently become `admin`. There is no DB-level
  `role` default.
- **Parameterized queries.** All DB access goes through GORM with bound
  parameters — no string-built SQL.

## Operator responsibilities (you must configure these)

- **bcrypt cost 12.** `package:install` sets `bcrypt.rounds: 12` in
  `config/hashing.go`; keep it (required for hashing to work and to stay
  compatible with existing `$2a$12$` hashes).
- **`http.trusted_proxies` (REQUIRED with rate-limiting or audit logging).** The
  rate-limiter and the audit log key on `ctx.Request().Ip()`, which honours
  `X-Forwarded-For`. Behind a proxy/CDN you **must** set the trusted-proxy list.
  If you do not, any client can forge `X-Forwarded-For` to **bypass the login
  rate limit** (each spoofed IP gets a fresh window) and to **forge the IP
  recorded in the audit log**. This is mandatory whenever
  `authkit.features.audit_log` or login rate-limiting is enabled.
- **Production cookie flags.** Set `session.secure=true` and a `session.same_site`
  of `lax` (typical for SPAs) or `strict`. SameSite remains defense in depth in
  addition to Authkit's origin verification.
- **Shared limiter backend for multiple instances.** The memory store cannot
  coordinate processes. Register a Redis or equivalent atomic store before
  routes when the app runs more than one instance. Store errors fail closed with
  `503 rate_limiter_unavailable`.
- **TLS.** Serve over HTTPS so the session cookie is never sent in clear.

## Two-factor (TOTP)

When `authkit.features.two_factor` is on, users can enroll in TOTP
(RFC 6238, Google-Authenticator compatible, via `github.com/pquerna/otp`):

- **The TOTP secret is encrypted at rest** with the Goravel `Crypt` facade (app
  key); the column is `json:"-"` and never serialized or logged. (It must be
  reversible so codes can be validated.)
- **Recovery codes are stored as one-way SHA-256 hashes**, not reversibly
  encrypted. The plaintext codes are shown **exactly once**, at confirmation /
  regeneration; they can never be re-derived afterwards. The
  `GET /auth/two-factor/recovery-codes` endpoint returns only the count of
  unused codes — if a user loses their codes they must regenerate.
- **Two-step login.** A correct password for a 2FA user returns
  `{two_factor:true}` and stashes only the user id in the session — the session
  is **not** authenticated until the challenge succeeds.
- **The challenge endpoint is rate-limited** (same limiter as login) because a
  6-digit code is brute-forceable.
- **Recovery codes are single-use**, stored hashed (see above), and can be
  regenerated (which invalidates the old set). Consumption is atomic (row-locked
  transaction) so a code cannot be double-spent under concurrency. The challenge
  accepts a TOTP code or a recovery code.
- **TOTP codes are single-use within their window** (OWASP ASVS 2.8.4): the
  accepted code's time-step is recorded and a replayed code is rejected.
  Validation allows ±1 period of clock skew.
- **Disabling 2FA requires re-authentication** with the account password, so a
  stolen session alone cannot silently remove 2FA.

## Impersonation

When `authkit.impersonation.enabled` is on, an authorized actor can switch into
another user's session ("login as user") — within its own guard or across guards.
Because this **bypasses the target's password by design**, authorization is the
*only* gate, so it must be strong and the activity must be audited.

- **Fail-closed gate.** Impersonation is off by default. A per-actor-guard config
  gate decides who may impersonate whom: `roles` (the actor must hold one — empty =
  any authenticated user in this guard), `target_guards` (which guards may be
  targeted; **empty = this guard cannot impersonate at all**), and `protected_roles`
  (targets holding one of these can never be impersonated). A guard with no gate
  config cannot impersonate (it can still be a target of another guard).
- **Optional host hook.** `authkit.RegisterImpersonationPolicy` registers an
  `authkit.Impersonator` for finer rules (tenant scoping, relationship checks). It
  runs **only after** the config gate has passed, so it can only ever *tighten* the
  decision — never loosen it. With no hook, the config gate alone decides.
- **Audited.** Every switch and exit is written to the audit log
  (`auth.impersonation_started` / `auth.impersonation_stopped`, with actor/target
  ids and both guards in the metadata).
- **Ephemeral — no remember cookie.** A switch issues **no** persistent
  remember-me cookie and no active-session tracking token, so it cannot be restored
  from a stored cookie; it lives only for the current session and ends on "stop".
- **Target must be live.** The target user must exist and must not be disabled;
  `protected_roles` blocks impersonating privileged accounts.
- **Reject while impersonating.** While a switch is active, the guard blocks the
  credential- and privilege-sensitive routes — password change
  (`PUT /auth/password`), user management (`/auth/users*`) and a nested
  impersonation — with `403 impersonation_forbidden`, so an actor acting "as" a user
  cannot change that user's password, manage users as them, or chain switches.
- **Session-id regeneration** happens on both the switch and the stop
  (anti-fixation), the same as login. `GET /auth/me` exposes `impersonatedBy` while
  impersonating so a UI can show a banner and an exit control.

## Multi-guard session isolation

With multiple guards the domains share one session cookie on a single origin
(Goravel keys each guard's user id separately). Active-session tracking is keyed by
a **stable per-guard token** stored in the session — not the Goravel session id,
which rotates on every login (anti-fixation). So concurrent logins to several guards
in one browser all keep working: a second guard's login rotates the session id but
the first guard's token (and its tracking row) survives.

For stronger isolation — so a flaw in one (e.g. customer) portal cannot reach
another (e.g. admin) on the same origin — **run each portal on its own
subdomain/origin** so the browser separates their cookies. A distinct per-guard
session cookie name/path is an optional knob for single-origin setups.

## Known limitations (by design)

- **Single-role authorization only.** There is one `role` string per user and a
  single privileged role (`admin`, configurable via
  `authkit.user_management_roles`). The `/users` endpoints are gated behind it
  (fail-closed default `["admin"]`), and the package keeps at least one active
  admin (you cannot delete, disable, demote, or self-disable the last admin).
  Reaching `/users` already requires admin, so an admin assigning any allowed
  `role` is intended. Full roles/permissions tables (multiple privileges,
  per-resource grants) are a later phase.
- **No account lockout, email verification, or password reset** in v1 — these
  are on the roadmap and need a configured mailer.

## Audit trail

When `EnableAuditLog` is on, the package writes to the guard's audit table
(`audit_logs` by default, `<guard>_audit_logs` for a named guard):

| Action | When |
| --- | --- |
| `auth.login` | Successful login |
| `auth.login_remember` | Silent re-login from a remember cookie |
| `auth.login_failed` | Failed login (attempted email in metadata) |
| `auth.logout` | Logout |
| `auth.password_changed` | Self-service password change |
| `auth.api_token_created` / `auth.api_token_revoked` / `auth.api_tokens_revoked` | Personal API-token lifecycle |
| `user.create` / `user.update` / `user.delete` | User management |
| `user.password_reset` | Admin set-password |
| `auth.two_factor_enrolled` / `auth.two_factor_confirmed` | 2FA enrollment |
| `auth.two_factor_disabled` / `auth.two_factor_recovery_regenerated` | 2FA changes |
| `auth.two_factor_failed` | Failed 2FA challenge |
| `auth.impersonation_started` / `auth.impersonation_stopped` | An actor switched into / out of another user's session |

Audit writes are best-effort: a write failure is logged but does not fail the
parent request.

Administrators can inspect successful sign-ins for their current guard through
`GET {prefix}/auth/admin/logins`. The endpoint is server-paginated, supports
literal user/IP filtering, sign-in-method filtering, and timestamp sorting. It
uses the same fail-closed roles as user management and is blocked while
impersonating.
It joins the audit actor to the live user only to display the current name and
email; deleted users retain the email snapshot stored with their audit event.
Correct `http.trusted_proxies` configuration remains mandatory because the
displayed IP comes from Goravel's trusted request IP resolution.

## Reporting

This is authentication code. If you find a security issue, please report it
privately to the maintainers rather than opening a public issue.
