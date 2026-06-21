# API Reference

All paths are prefixed with `Options.Prefix` (default `/api/v1`). The `@ID`
column is the Swagger operation id — it becomes the generated TypeScript SDK
function name. Auth endpoints other than login require the session cookie
(guarded by `Authenticated`).

## Auth

| Method | Path | `@ID` | Auth | Success | Errors |
| --- | --- | --- | --- | --- | --- |
| POST | `/auth/login` | `login` | public (rate-limited) | `200` UserResponse | `400` `401` `429` `500` |
| POST | `/auth/logout` | `logout` | cookie | `200` MessageResponse | `401` |
| GET | `/auth/me` | `getMe` | cookie | `200` UserResponse | `401` |
| PUT | `/auth/password` | `changePassword` | cookie | `200` MessageResponse | `400` `401` `500` |

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
| GET | `/users` | `listUsers` | `200` `[]UserResponse` | `401` |
| POST | `/users` | `createUser` | `201` UserResponse | `400` `409` |
| GET | `/users/{id}` | `getUser` | `200` UserResponse | `404` |
| PUT | `/users/{id}` | `updateUser` | `200` UserResponse | `400` `404` `409` |
| DELETE | `/users/{id}` | `deleteUser` | `200` MessageResponse | `400` `404` `409` |
| POST | `/users/{id}/password` | `setUserPassword` | `200` UserResponse | `400` `404` |

## Request bodies

```jsonc
// LoginRequest
{ "email": "admin@example.com", "password": "secret" }

// ChangePasswordRequest
{ "currentPassword": "secret", "newPassword": "new-secret" }

// CreateUserRequest
{ "email": "jane@example.com", "name": "Jane Admin", "password": "secret", "role": "admin" }

// UpdateUserRequest
{ "email": "jane@example.com", "name": "Jane Admin", "role": "admin" }

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
  "createdAt": "2026-01-01T00:00:00Z"
}

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
