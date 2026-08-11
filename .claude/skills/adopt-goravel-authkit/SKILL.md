---
name: adopt-goravel-authkit
description: Adopt the current github.com/freshost/goravel-authkit package into a Goravel 1.18 and Vite/React application, replacing bespoke authentication while preserving user data and security boundaries. Use for fresh installs, migrations from existing login and user-management code, single-guard or multi-guard setups, host-route protection, impersonation, the @freshost/authkit-ui frontend, and end-to-end adoption verification.
---

# Adopt goravel-authkit

Work inside the consuming Goravel application. Treat the Authkit repository,
its public API, documentation, tests, and `CHANGELOG.md` as authoritative. Read
`docs/installation.md`, `docs/configuration.md`, `docs/security.md`, and
`docs/api-reference.md` from the exact Authkit revision being adopted.

Use the current source baseline: Go 1.25+, Goravel 1.18, multi-guard support,
impersonation, fail-closed CSRF origin verification, service-owned email
validation, and combined IP plus account/user rate limits. Do not add Goravel
1.17 compatibility branches or restore removed Authkit APIs. When consuming a
published module, pin a real release tag containing the required behavior; do
not invent a version for unreleased changes.

## Preserve these boundaries

- Let Authkit own its canonical user model, authentication orchestration,
  authorization, sessions, remember tokens, TOTP, audit records, and optional
  user management.
- Keep each existing user domain as a separate guard and table. Do not merge
  customer and staff identities merely to adopt Authkit.
- Keep domain validation in services. Do not rely on HTTP binding as the only
  email, password, role, or authorization check.
- Pass `context.Context` through service and persistence calls.
- Keep PostgreSQL authoritative for migrations, UUIDs, JSON, constraints,
  transactions, and locking.
- Never log credentials, password hashes, session or remember tokens, recovery
  codes, TOTP secrets, or internal provider errors.
- Keep machine-to-machine bearer authentication separate from cookie-backed
  Authkit routes.

## Choose the adoption path

- Use the fresh-app path when no authentication tables or flows exist.
- Use the single-domain migration path when one existing user table backs one
  login flow.
- Use the multi-guard path when the app has separate identity domains such as
  `admin_users` and `accounts`.

Before changing an existing app, inventory its user tables, password hashing,
guards, login/logout/password-reset flows, sessions, remember-me behavior, 2FA,
user CRUD, roles, impersonation or “login as” behavior, protected host routes,
API clients, proxy topology, and production instance count.

## Install and mount

For a fresh or published dependency:

```bash
go get github.com/freshost/goravel-authkit@<release>
./artisan package:install github.com/freshost/goravel-authkit
```

For a local checkout, use an explicit `replace` directive and register
`&authkit.ServiceProvider{}` in `bootstrap/providers.go`.

`package:install` registers the provider and writes the package-owned
`config/authkit.go`. If `config/auth.go` or `config/hashing.go` already exists,
the installer makes additive edits for the default guard and bcrypt cost. The
provider can auto-register configured guards and migrations, so neither file is
required in a fresh app.

Mount routes exactly once from the host routing callback:

```go
import authkitroutes "github.com/freshost/goravel-authkit/routes"

foundation.Setup().
	WithRouting(func() {
		routes.Web()
		authkitroutes.RegisterAll(facades.Route())
	})
```

Treat this as Authkit's stable, explicit mount contract. It keeps configured
dynamic guards visible in host routing and avoids duplicate registration. Do
not claim Goravel 1.18 discards routes registered by provider `Boot`; its
middleware configuration now runs before providers boot.

Authkit starts sessions on its own route groups. Add `StartSession` only to the
host's own session-backed routes, preferably per group. Do not put session
middleware on stateless bearer APIs or health endpoints without a reason.

## Configure security before exposing routes

Start from `setup/config/authkit.go` in the adopted Authkit revision. Preserve
these secure defaults:

```go
"rate_limit": map[string]any{
	"ip_attempts":       20,
	"account_attempts":  5,
	"password_attempts": 5,
	"window":            60,
},
"csrf": map[string]any{
	"enabled":         true,
	"trusted_origins": []string{},
},
"user_management_roles": []string{"admin"},
```

Do not restore the removed `rate_limit.attempts` key or `RateLimitAuth`
middleware. Login and 2FA consume both an IP bucket and a normalized
account/user bucket; password changes consume IP and authenticated-user
buckets.

Keep CSRF verification enabled. Every state-changing Authkit route, including
host routes wrapped by `routes.Protect` or `routes.ProtectRole`, requires one of:

- a same-origin or explicitly trusted `Origin`;
- a same-origin or explicitly trusted `Referer`; or
- `Sec-Fetch-Site: same-origin`.

For a cross-origin SPA, list only its exact scheme and host in
`authkit.csrf.trusted_origins`. Browser clients should send credentials. CLI,
server-to-server, and test clients must send an explicit accepted `Origin`.
Expect an unverifiable or untrusted unsafe request to fail with
`403 csrf_failed`.

Set `http.trusted_proxies` to the exact proxy/CDN hops before relying on client
IP rate limits or audit IPs. Never trust arbitrary forwarded headers.

The default limiter is process-local. In every multi-instance deployment,
register one atomic shared backend such as Redis before calling `RegisterAll`:

```go
type sharedLimiter struct { /* shared client */ }

func (store *sharedLimiter) Hit(
	ctx context.Context,
	key string,
	limit int,
	window time.Duration,
) (authkit.RateLimitResult, error) {
	// Atomically consume an attempt and create or retain the bucket expiry.
}

authkit.RegisterRateLimitStore(&sharedLimiter{})
authkitroutes.RegisterAll(facades.Route())
```

Implement `Hit` atomically across processes. Authkit supplies namespaced,
SHA-256-hashed keys, so do not try to recover raw email, IP, or user IDs from
them. Preserve fail-closed backend errors as
`503 rate_limiter_unavailable`.

## Adopt a fresh app

1. Install the package and mount routes once.
2. Review `config/authkit.go`; disable only features the app intentionally does
   not expose.
3. Set bcrypt rounds to 12 when matching this stack.
4. Run migrations against the intended PostgreSQL database.
5. Create the bootstrap administrator:

```bash
./artisan migrate
./artisan auth:create-user --email=admin@example.com --password=<secret>
```

The command targets the default `users` table. Use the programmatic API for a
guard backed by another table.

## Migrate one existing user domain

Configure single-guard mode with top-level `authkit.guard`,
`authkit.route_prefix`, feature, role, rate-limit, and CSRF keys. Leave
`authkit.guards` absent.

Reshape the existing table to Authkit's canonical columns before running its
migrations. Required data includes a UUID primary key, unique email,
`password_hash`, `password_changed_at`, role, disabled timestamp, verification
and profile fields, nullable `two_factor_*` fields, and timestamps. Keep extra
application columns. Preserve compatible bcrypt hashes; never hash an existing
hash again.

Audit existing email data before cutover:

- reject or repair malformed addresses that service-level validation will no
  longer accept;
- normalize the same way as Authkit and resolve case/whitespace collisions
  before creating a unique constraint; and
- test direct service or command callers, not only HTTP controllers.

Let idempotent Authkit migrations add missing columns and supporting audit,
remember-token, and session tables. Then remove the old controllers, services,
repositories, middleware, routes, model wiring, session helpers, and bootstrap
user command only after no call sites remain.

Use `authkitroutes.AuthUserID(ctx)` when host domain handlers need the current
Authkit user ID.

## Keep multiple user domains separate

Declare one entry under `authkit.guards` per domain. Put shared defaults at the
top level and override guard-specific prefixes, tables, roles, features,
password length, rate limits, CSRF settings, 2FA, remember settings, and
impersonation gates only where necessary:

```go
"guards": map[string]any{
	"admin": map[string]any{
		"prefix":      "/api/admin/v1",
		"users_table": "admin_users",
	},
	"client": map[string]any{
		"prefix":              "/api/v1",
		"users_table":         "accounts",
		"min_password_length": 12,
	},
},
```

Give guards on one origin distinct remember-cookie names; the defaults already
use `authkit_<guard>_remember`.

When the host owns existing tables, set `register_migrations=false` and append
`migrations.ForTables(migrations.MigrationConfig{UsersTable: "...", APITokensTable: "..."})`
for each guard. Keep `register_guards=true` unless the host deliberately owns Goravel
guard definitions. Never use `auth:create-user` for a non-default table; use:

```go
kit := authkit.New(authkit.Config{Guard: "client", UsersTable: "accounts"})
_, err := kit.CreateUser(ctx, "customer@example.com", "Jane", "<secret>", "user")
```

## Protect host routes

Use Authkit's complete middleware chain rather than reconstructing it:

```go
facades.Route().Prefix("/api/v1/portal").
	Middleware(authkitroutes.Protect("client")...).
	Group(func(r route.Router) {
		r.Get("/whoami", handler)
	})
```

Use `ProtectRole("client", "admin")` for a role gate. These chains include
session startup, CSRF behavior for unsafe methods, authentication, and the
optional role check. Do not reconstruct or reorder that chain in the host.

For non-browser integrations, enable `features.api_tokens` explicitly and define
the smallest `api_tokens.allowed_scopes` allow-list. Use
`ProtectToken(guard, scopes...)` for token-only routes or
`ProtectAny(guard, scopes...)` for routes that also accept browser sessions.
Never persist the one-time plaintext token in application logs, frontend storage,
fixtures, or config. Keep token management session-only and run
`auth:prune-api-tokens` on a daily schedule.

## Configure impersonation explicitly

Keep impersonation off unless the product requires it. Enabling the global
switch is insufficient by design: each actor guard also needs an explicit,
fail-closed gate.

```go
"impersonation": map[string]any{"enabled": true},
"guards": map[string]any{
	"admin": map[string]any{
		"prefix":      "/api/admin/v1",
		"users_table": "admin_users",
		"impersonation": map[string]any{
			"roles":           []string{"admin"},
			"target_guards":   []string{"client"},
			"protected_roles": []string{"admin"},
		},
	},
},
```

Treat an empty `target_guards` as deny-all. Use
`authkit.RegisterImpersonationPolicy` only to tighten the config gate for tenant
or relationship rules. Preserve audit events, session-ID regeneration, the lack
of a remember cookie during impersonation, and rejection of password changes,
user management, and nested impersonation while switched. Ensure the UI always
shows `impersonatedBy` and offers a visible stop action.

When replacing an existing “login as” implementation, compare its actor roles,
target domains, protected roles, tenant boundaries, audit trail, and exit
semantics before removing it.

## Adopt the React companion

Use `@freshost/authkit-ui` instead of the consuming app's duplicate login,
account, 2FA, session, and user-management pages. Read its README from the exact
revision installed.

Place `AuthkitProvider` inside the existing query, i18n, and router providers.
Pass the guard prefix as `baseURL`, preserve the app's `QueryClient` defaults,
and provide the app's notification adapter. Use one provider per portal in a
multi-guard frontend. Ensure its HTTP client includes browser credentials and
that cross-origin deployments match `authkit.csrf.trusted_origins` exactly.

Do not expect generated OpenAPI clients to contain Authkit endpoints. Dynamic
guard routes have no Swagger annotations; use the companion's typed client or
the route shapes in `docs/api-reference.md`.

## Verify the completed adoption

Run the consuming backend's formatter, tidy, tests, race tests, vet, migrations,
and feature suite against PostgreSQL. Verify at least:

1. Login sets a session cookie and `/auth/me` returns the correct guard user.
2. Wrong-password and unknown-email responses are indistinguishable.
3. Malformed emails fail through HTTP and direct service/command paths.
4. Password change invalidates other sessions but preserves the current one.
5. User CRUD enforces role, self-delete, last-admin, and disabled-user rules.
6. Existing users retain access with their existing compatible password hashes.
7. Multi-guard sessions, tables, features, cookies, and prefixes remain isolated.
8. Protected host routes reject unauthenticated users and expose the correct ID.
9. Unsafe requests without a trusted origin signal return `403 csrf_failed`;
   same-origin and explicitly trusted requests succeed.
10. IP plus account/user buckets return the intended `429` and retry timing;
    password-change limits are independent.
11. A limiter backend failure returns `503 rate_limiter_unavailable`; a
    multi-instance test proves a shared bucket is enforced across instances.
12. Trusted-proxy tests prove the rate-limit and audit IP cannot be forged.
13. 2FA, remember-me, active-session termination, and recovery codes work when
    enabled without exposing their secrets.
14. Impersonation remains off by default; when enabled, its gate, protected
    roles, audit, no-nesting rule, sensitive-action rejection, and stop flow work.
15. PostgreSQL migrations and rollback succeed on the real target schema.

Inspect the final diff for lost host behavior, duplicate route registration,
weakened defaults, secrets, generated artifacts, and stale references to removed
Authkit APIs.

## Diagnose common failures

- `403 csrf_failed` on every unsafe request: send an accepted `Origin` or
  `Referer`, or configure the exact cross-origin SPA origin. Do not disable CSRF
  as the first fix.
- `503 rate_limiter_unavailable`: repair the registered shared backend; Authkit
  intentionally fails closed.
- Limits differ between replicas: register one atomic shared store before route
  mounting on every instance.
- Client IP or audit IP is wrong: correct `http.trusted_proxies`; do not trust
  arbitrary `X-Forwarded-For` values.
- User columns remain missing: reshape before migration, or register
  `migrations.ForTables(...)` for every host-owned table.
- A non-default guard has no bootstrap user: use `authkit.New(...).CreateUser`.
- Two guards overwrite remember cookies: assign distinct cookie names.
- Authkit endpoints are absent from generated SDKs: expected; use the companion
  client or document the dynamic routes separately.
- Middleware code fails on Goravel 1.17: upgrade the consumer to 1.18. Do not add
  compatibility wrappers around the old function middleware contract.
