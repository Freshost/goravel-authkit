# OpenID Connect provider

Authkit can act as an OpenID Connect Provider and OAuth authorization server.
This is part of the existing Go module and is disabled by default. It uses
`github.com/zitadel/oidc/v3` for protocol processing and Authkit's accounts,
browser sessions and two-factor authentication for user authentication.

This feature does **not** implement signing in to Authkit through an external
OIDC provider. That future feature is the OIDC **client** role. Registered
**clients** below are applications receiving tokens from this Authkit provider.

## Supported profile

- OIDC Authorization Code Flow; PKCE `S256` is required for every client.
- Public web/native clients (`token_endpoint_auth_method: none`) and confidential
  web clients (`client_secret_basic`). PKCE does not replace client authentication.
- Discovery, JWKS, UserInfo, refresh grants and RFC 7009 revocation.
- `query` and `form_post` authorization responses; `none`, `login`, `consent` and
  `select_account` prompts. The host login UI must support interactive account
  selection/reauthentication when requested.
- Public subjects: the stable user UUID, scoped by the issuer. Emails are not
  identifiers. Claims are scope-limited; `email_verified` comes from stored
  verification state, not the presence of an email address.
- RS256-signed ID tokens and opaque, server-validated bearer access tokens.

Implicit/hybrid flows, password grants, client credentials, dynamic registration,
device flow, token exchange, introspection and OIDC logout extensions are not
enabled or advertised. Configure ordinary OIDC clients through discovery; no
Authkit-specific token exchange or client SDK is needed.

Conformance of the integrated provider must be verified separately from the
upstream library. See [conformance verification](oidc-conformance.md). Do not
describe an unverified integration as certified.

## Requirements and configuration

Authkit requires Go 1.26+, including when OIDC is disabled. The provider's
persistence and concurrency tests target PostgreSQL. Existing session and
personal API-token contracts are unchanged.

Configure one provider issuer and explicitly bind it to an existing Authkit guard:

```go
"oidc": map[string]any{
    "provider": map[string]any{
        "enabled": true,
        "guard": "client",
        "issuer": "https://accounts.example.com/oidc",
        "login_url": "/login",
        "signing_key_id": "signing-2026-11",
        "signing_keys": config.Env("AUTHKIT_OIDC_SIGNING_KEYS"),
        "encryption_key_id": "encryption-2026-11",
        "encryption_keys": map[string]any{
            "encryption-2026-11": config.Env("AUTHKIT_OIDC_ENCRYPTION_KEY"),
        },
        "scopes": []string{"api:read", "api:write"},
        "cors": map[string]any{
            "allowed_origins": []string{"https://app.example.com"},
        },
    },
},
```

The issuer is a stable HTTPS URL without a trailing slash, query, credentials or
fragment. It is never inferred from request/proxy headers. Changing the issuer
creates a different identity namespace. This initial version binds one issuer
to one guard; it does not merge accounts across guards.

`signing_keys` is a JSON Web Key Set containing an RSA private signing key with
the selected `kid`, plus public keys retained for verification. RSA keys must be
at least 2048 bits. `encryption_keys` maps key IDs to base64-encoded 32-byte AES
keys; select one for new authenticated GCM encryption. Use persistent keys shared
by every application instance. No production keys are generated at startup.
Keep old verification/decryption keys through the relevant token/code lifetime
and clock allowance before removing them. JWKS publishes public material only.

`openid`, `profile`, `email` and `offline_access` are built-in scopes; `scopes`
adds host-defined API scopes. Each client has its own allowed subset and API
audiences. OIDC scopes never grant workspace/project permissions.

Default lifetimes, configurable in seconds:

| Setting | Default |
| --- | ---: |
| `access_token_lifetime_seconds` | 300 |
| `id_token_lifetime_seconds` | 300 |
| `code_lifetime_seconds` | 120 |
| `request_lifetime_seconds` | 600 |
| `refresh_idle_lifetime_seconds` | 2592000 (30 days) |
| `refresh_absolute_lifetime_seconds` | 7776000 (90 days) |

For isolated development/testing, `allow_insecure_loopback` permits an HTTP
issuer at `127.0.0.1` or `::1`. It does not permit arbitrary HTTP issuers.
Registered native loopback callbacks can use HTTP independently of this setting.

`routes.RegisterAll` mounts the provider automatically when enabled. With
`authkit.register_migrations = false`, explicitly register `oidc.Migrations()`.
When disabled, no provider routes, migration registrations or key requirements
are added. `routes.RegisterOIDC` is available for hosts mounting routes manually;
do not call it in addition to `RegisterAll`.

## Register applications

Client registration is an administrative service operation, not a public
Dynamic Client Registration endpoint. Example administrative metadata file:

```json
{
  "client_id": "example-web",
  "client_name": "Example application",
  "application_type": "web",
  "token_endpoint_auth_method": "none",
  "redirect_uris": ["https://app.example.com/callback"],
  "scopes": ["openid", "profile", "email", "offline_access", "api:read"],
  "audience": ["https://api.example.com"],
  "allow_refresh": true,
  "skip_consent": false
}
```

```bash
./artisan auth:oidc-client --file=/secure/path/client.json
./artisan auth:oidc-client --disable=example-web
```

For confidential web clients, use `client_secret_basic` and supply the secret in
`AUTHKIT_OIDC_CLIENT_SECRET` to the command. Use a random 32–72 byte secret.
Only a password hash is persisted;
the command never prints credentials. Public clients must not have a secret.
Programmatic callers can obtain `routes.NewOIDCProvider()` and call
`provider.Service.RegisterClient(ctx, client, secret)` or `DisableClient`.
Every update advances the client version and invalidates its previous grants.

Redirects match registered values exactly. Native loopback redirects allow a
different port only; scheme, literal host, path and query remain bound. Native
private-use schemes must use a reverse-domain-style scheme. No wildcard redirects
or general localhost/HTTP exceptions are enabled.

## Browser authentication and consent

The provider redirects to the configured login UI with a controlled `return_to`
pointing to its own interaction endpoint. The host UI completes the existing
Authkit login/2FA flow, then navigates back to that continuation. Validate this
destination against the expected issuer/interaction path; never accept arbitrary
redirect destinations. Honor `prompt=login` rather than immediately skipping the
form because a browser session already exists.

Use secure, HttpOnly session cookies with `SameSite=Lax` for top-level browser
authorization navigation. `SameSite=Strict` can prevent reuse of an existing
login when another site's application initiates authorization.

Current Authkit logins record authentication time, event ID, verified methods and
the enrolled 2FA credential version. Existing sessions with this information can
be reused. Legacy sessions and remember-cookie restorations have no trustworthy
interactive proof and require a new interactive login for provider authorization.
Remember rotation is never presented as a fresh password or MFA authentication.

A minimal consent page is provided. It displays the account, client and scopes;
approval is bound to that account/authentication event, browser and request.
Changing accounts in another tab invalidates an outstanding approval. Previously
authorized live scopes can be reused; `prompt=consent` always requests approval.
`skip_consent` is an explicit administrative preauthorization policy for trusted
applications, including any permitted offline access. It is false by default.
`prompt=none` returns standard interaction errors when login or consent is needed.

Authorizations are refused while impersonating, including cross-guard switches.
Browser mutations retain origin/CSRF protection; token and revocation requests
use protocol credentials and do not require a browser Origin header. Stateless
CORS origins are configured separately and do not enable cookies.

## Protect API routes

```go
facades.Route().Prefix("/api/v1/projects").
    Middleware(authkitroutes.ProtectSessionOrOIDC(
        "client", "https://api.example.com", "api:read",
    )...).Group(func(r route.Router) {
        // Register host-owned handlers here.
    })
```

Use `ProtectOIDC` for bearer-only endpoints. `ProtectSessionOrOIDC` preserves
session CSRF protection and never falls back to a cookie after a supplied invalid
Authorization header. Existing `ProtectToken`/`ProtectAny` remain personal-token
helpers; they do not silently start accepting OIDC tokens.

Read the user through `routes.AuthUserID`, and OIDC client/connection/scopes
through `helpers.OIDCClientID`, `OIDCConnectionID` and `OIDCScopes`. Enforce live
resource permissions in the host service. ID tokens are not API access tokens.

## Credential lifecycle

- Each authorization creates an independently revocable connection. A connection
  identifies an authorization grant, not a verified physical device.
- Refresh tokens are hashed at rest and rotate atomically. Reuse revokes the
  family, including its access tokens. Clients must serialize refreshes and
  reauthenticate after an ambiguous failed rotation; automatic reuse retries can
  trigger compromise detection.
- A repeated valid authorization-code exchange revokes its issued grant. Invalid
  PKCE/client/redirect attempts do not consume the code or revoke another grant.
- PostgreSQL transactions enforce single use. Spent records remain for replay
  detection. Token signing/encryption failure after a committed rotation fails
  closed; it can require a new authorization.
- Access and refresh validation checks the live user, password epoch, enrolled
  2FA credential, client version, grant status, expiry, audience and scopes.
  Password changes/resets, account disable/delete and 2FA disable/re-enrollment
  invalidate old grants. Refresh never advances the original authentication
  epoch or absolute grant expiry. Merely regenerating recovery-code inventory
  does not change the enrolled credential; explicitly revoke connections when
  the host's incident policy requires it.
- Browser logout terminates the browser session; it does not revoke independent
  applications. Application logout should use the standard revocation endpoint
  and remove its local credentials. Offline local deletion cannot guarantee
  server-side revocation.

Session-only connection management lives at
`{authkit_prefix}/auth/oidc/connections`: GET lists live connections, DELETE with
`/{id}` revokes one, and DELETE on the collection revokes all current connections.
The endpoints enforce remote session termination and reject impersonation.

Schedule `auth:prune-oidc` daily. Records are retained until their grant's absolute
expiry plus 30 days. With audit enabled, client registration/deactivation,
issuance, reuse detection and connection revocation produce identifier-only
events. Authentication/issuance fails closed if security state cannot be read.
The HTTP adapter uses the guard's shared rate-limit store; configure trusted
proxies and a distributed limiter for multiple instances. Its IP limit inherits
the guard's limit unless overridden by `oidc.provider.rate_limit.ip_attempts`;
the published configuration sets this to 120 requests per guard rate-limit window.
