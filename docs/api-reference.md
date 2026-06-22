# API Reference

Every package route lives under **`{Options.Prefix}/auth`** (default
`/api/v1/auth`) — a single owned namespace so the package never collides with the
host app's own routes (its `/meta`, `/users`, …). The paths below are relative to
that base. The `@ID` column is the Swagger operation id — it becomes the
generated TypeScript SDK function name. Auth endpoints other than login require
the session cookie (guarded by `Authenticated`).

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

## Sessions (when `features.sessions`)

| Method | Path | `@ID` | Auth | Success | Errors |
| --- | --- | --- | --- | --- | --- |
| GET | `/auth/sessions` | `listSessions` | cookie | `200` `[]SessionResponse` | `401` |
| DELETE | `/auth/sessions` | `terminateOtherSessions` | cookie | `200` MessageResponse | `401` |
| DELETE | `/auth/sessions/{id}` | `terminateSession` | cookie | `200` MessageResponse | `400` `404` |

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
| GET | `/auth/two-factor/recovery-codes` | `getTwoFactorRecoveryCodes` | cookie | `200` RecoveryCodesResponse | `401` |
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
  "createdAt": "2026-01-01T00:00:00Z"
}

// MetaResponse — GET /auth/meta (public; the UI reads roles/features from here)
{
  "roles": ["admin", "user"],
  "minPasswordLength": 8,
  "features": { "userManagement": true, "twoFactor": true, "auditLog": true, "sessions": true }
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

// MessageResponse
{ "message": "Password changed" }

// TwoFactorRequiredResponse — login when 2FA is enabled
{ "two_factor": true }

// TwoFactorEnrollmentResponse
{ "secret": "JBSWY3DPEHPK3PXP", "otpauthUrl": "otpauth://totp/App:admin@example.com?secret=...&issuer=App" }

// RecoveryCodesResponse
{ "recoveryCodes": ["ABCDE-FGHJK", "..."] }

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
| 403 | `forbidden` | `RequireRole` gate failed |
| 404 | `not_found` | User does not exist |
| 409 | `already_exists` | Email already taken |
| 409 | `last_admin` | Deleting the last user |
| 429 | `rate_limited` | Too many login attempts |

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
