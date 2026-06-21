# Security model

`goravel-authkit` is session-cookie authentication. This document states the
guarantees, the operator responsibilities, and the known v1 limitations.

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
  `password_changed_at` captured at login; the `Authenticated` middleware
  compares it to the live DB value on every request. A password change bumps the
  DB value, so every *other* session is rejected (`401 session_expired`) on its
  next request. The session that changed the password is re-stamped and stays in.
- **Login rate-limiting.** A per-IP sliding window (default 5/min) on
  `/auth/login`, with periodic eviction so the in-memory limiter cannot grow
  unboundedly.
- **Parameterized queries.** All DB access goes through GORM with bound
  parameters — no string-built SQL.

## Operator responsibilities (you must configure these)

- **bcrypt cost 12.** `package:install` sets `bcrypt.rounds: 12` in
  `config/hashing.go`; keep it (required for hashing to work and to stay
  compatible with existing `$2a$12$` hashes).
- **`http.trusted_proxies`.** The rate-limiter and the audit log key on
  `ctx.Request().Ip()`, which honours `X-Forwarded-For`. Behind a proxy/CDN you
  **must** set the trusted-proxy list, or an attacker can bypass the rate limit
  and spoof audit IPs by forging the header.
- **Production cookie flags.** Set `session.secure=true` and a `session.same_site`
  of `lax` (typical for SPAs) or `strict`. Cookie-based auth relies on SameSite
  for CSRF defense — there is no token-based CSRF protection.
- **TLS.** Serve over HTTPS so the session cookie is never sent in clear.

## Two-factor (TOTP)

When `authkit.features.two_factor` is on, users can enroll in TOTP
(RFC 6238, Google-Authenticator compatible, via `github.com/pquerna/otp`):

- **Secret + recovery codes are encrypted at rest** with the Goravel `Crypt`
  facade (app key); both columns are `json:"-"` and never serialized or logged.
- **Two-step login.** A correct password for a 2FA user returns
  `{two_factor:true}` and stashes only the user id in the session — the session
  is **not** authenticated until the challenge succeeds.
- **The challenge endpoint is rate-limited** (same limiter as login) because a
  6-digit code is brute-forceable.
- **Recovery codes are single-use**, stored encrypted, and can be regenerated
  (which invalidates the old set). Consumption is atomic (row-locked
  transaction) so a code cannot be double-spent under concurrency. The challenge
  accepts a TOTP code or a recovery code.
- **TOTP codes are single-use within their window** (OWASP ASVS 2.8.4): the
  accepted code's time-step is recorded and a replayed code is rejected.
  Validation allows ±1 period of clock skew.
- **Disabling 2FA requires re-authentication** with the account password, so a
  stolen session alone cannot silently remove 2FA.

## Known v1 limitations (by design)

- **No RBAC.** The `/users` management endpoints are protected only by the
  session guard — every authenticated user can manage users and assign any
  `role`. For a single-admin deployment this is fine. For multi-user, set
  `authkit.user_management_roles` (e.g. `[]string{"admin"}`) to add a
  `RequireRole` check (403 on mismatch). Full roles/permissions tables are a
  later phase.
- **Change-password is not separately rate-limited.** It sits behind the session
  guard (an attacker needs a valid session) and bcrypt is deliberately slow, but
  there is no per-user attempt cap yet.
- **No account lockout, email verification, or password reset** in v1 — these
  are on the roadmap and need a configured mailer.

## Audit trail

When `EnableAuditLog` is on, the package writes to `audit_logs`:

| Action | When |
| --- | --- |
| `auth.login` | Successful login |
| `auth.login_failed` | Failed login (attempted email in metadata) |
| `auth.logout` | Logout |
| `auth.password_changed` | Self-service password change |
| `user.create` / `user.update` / `user.delete` | User management |
| `user.password_reset` | Admin set-password |
| `auth.two_factor_enrolled` / `auth.two_factor_confirmed` | 2FA enrollment |
| `auth.two_factor_disabled` / `auth.two_factor_recovery_regenerated` | 2FA changes |
| `auth.two_factor_failed` | Failed 2FA challenge |

Audit writes are best-effort: a write failure is logged but does not fail the
parent request.

## Reporting

This is authentication code. If you find a security issue, please report it
privately to the maintainers rather than opening a public issue.
