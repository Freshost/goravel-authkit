# Architecture

`goravel-auth` is a layered, app-agnostic Goravel package. It uses **only** the
upstream `github.com/goravel/framework/facades` (never app-local facade
wrappers), so it drops into any Goravel app regardless of that app's DI style.

## Layers

```
HTTP request
  └─ middleware/        Authenticated (session guard + password_changed_at), RateLimitAuth, RequireRole
  └─ http/controllers/  AuthController, UsersController — bind, map sentinel errors → {error,message}
        └─ services/    Auth, Users, Audit — validation + business rules + sentinel errors
              └─ repositories/  Users, Audit — GORM data access (interface seam for tests)
                    └─ models/   User (table "users"), AuditLog (table "audit_logs")
```

- **Controllers** are thin: bind the request, call a service, map sentinel errors
  to the `{"error","message"}` envelope with `net/http` status constants. Each
  carries Swagger annotations (`@ID` = camelCase = generated SDK function name).
- **Services** own validation and business rules and return sentinel errors
  (`ErrInvalidCredentials`, `ErrValidation`, `ErrNotFound`, `ErrAlreadyExists`,
  `ErrLastAdmin`, …). They take `context.Context` first and never touch the HTTP
  session — establishing the session is the controller's job.
- **Repositories** are the data-access seam. Services depend on the
  `UsersRepository` / `AuditRepository` interfaces, so they unit-test against an
  in-memory fake with no framework boot. The ORM implementations use
  `facades.Orm()`.
- **Hashing** is abstracted behind a `Hasher` interface (`FacadeHasher` wraps
  `facades.Hash()`), again for testability.

## The canonical User model

The package **owns** the `users` table and the `User` struct. There is no
extensibility mechanism — every adopting app shares the exact shape. It is
Auth.js-shaped (nullable `name`/`image`/`email_verified`, nullable
`password_hash` for a future OAuth flow), with `password_changed_at` for session
invalidation and a `role` string (used by the optional `RequireRole`).

## Goravel integration points

- **ServiceProvider** (`auth.ServiceProvider`) registers the `auth:create-user`
  command in `Boot`; it declares its framework dependencies via `Relationship()`
  (Config, Orm, Hash, Auth) so it boots after them. It registers no container
  bindings of its own — services are wired explicitly in `routes.Register`.
- **Migrations** are exported as `migrations.Migrations() []schema.Migration`,
  which the app appends to its own registry. They are idempotent (guard on
  `HasTable`).
- **Routes** are registered by the app calling `routes.Register(facades.Route(),
  opts)`. This is deliberate: it keeps the package controllers in the app's
  `main.go` import graph so `swag` scans their annotations into the OpenAPI
  contract (and thus the generated TS SDK). An auto-registration via
  `app.MakeRoute()` was avoided for that reason.
- **Config** is optional. `routes.OptionsFromConfig()` reads `authkit.*` keys
  with safe fallbacks; `routes.Register` also defaults every zero-valued Option.

## The SDK contract loop

The package's published routes + Swagger annotations are the stable contract.
Run the app's `make swagger` (→ `api/openapi.yaml`) and `make generate-api`
(hey-api → TS SDK). Because the operation ids are fixed (`login`, `getMe`,
`changePassword`, `listUsers`, …), the generated client is identical across
apps — which is what lets the companion `@freshost/auth-ui` package ship its own
thin typed client instead of depending on a per-app SDK.

## What is out of scope (frontend)

A Go package cannot ship React components into a pnpm workspace. The frontend
counterpart — login page, `useAuth` hooks, account/users pages — lives in the
separate `@freshost/auth-ui` npm package, consuming the contract above.

## Roadmap (post-v1)

Self-registration, email verification, password reset by email (needs a mailer),
and RBAC (roles/permissions tables + richer guards). The `RequireRole` hook and
the nullable `password_hash` are the seams left for these.
