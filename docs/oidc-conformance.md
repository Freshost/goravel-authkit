# OIDC conformance verification

The supported provider profile is documented in [OIDC](oidc.md). Compatibility
must be established for the integrated Authkit provider, not inferred from its
dependency. OpenID certification is a separate process; no certification is
claimed by adding the SDK.

Before a provider release:

1. Run the package test, race and vet gates and PostgreSQL demo feature tests in
   CI. This includes code/refresh concurrency, client/issuer binding, account
   invalidation, consent, PKCE and key rotation.
   An independent `coreos/go-oidc` client also exercises HTTPS discovery, public
   and confidential code flows, ID-token/JWKS validation, UserInfo and refresh.
2. Deploy the demo/host integration with a stable HTTPS issuer reachable by the
   [OpenID Foundation conformance suite](https://openid.net/certification/testing/).
   Supply an actual login UI that honors the documented reauthentication and
   continuation contract, plus an isolated test account.
3. Register the suite's confidential web client using `client_secret_basic`, its
   exact redirect URIs, `openid profile email` and the requested test secret.
   Register a public PKCE client separately. Grant refresh/offline access only
   to the test client exercising that extension.
4. Run the applicable Basic OP and provider-configuration tests, the advertised
   form-post profile, and PKCE/refresh/revocation interoperability tests. Exercise
   required request parameters and error responses, `prompt=none/login/consent`,
   `max_age`, ID-token hints, nonce, UserInfo, and signature/JWKS validation.
5. Record the exact revision, configuration, test-plan versions and results with
   the release review. Resolve failures before claiming conformance. Submit for
   certification separately if an OpenID Certified designation is desired.

The public client must use S256 without a client secret. The confidential client
must authenticate even when using PKCE. A client should require only discovery
and ordinary OAuth/OIDC configuration; any necessary proprietary client-side
workaround indicates an integration defect.

## Reproducible CI run

The `OIDC conformance` workflow runs the unmodified OpenID Foundation suite
`release-v5.3.4` (source revision `23353b36957d6466010de767c812d2c91ed37638`)
and its official Python runner. It runs Config OP, Basic OP and Form Post Basic
OP with static registration against the actual Goravel/Authkit integration and
PostgreSQL. The workflow uses official prebuilt suite images; all host builds
and verification run in CI.

`demo/conformance` is a separate CI executable. It supplies a minimal HTML login
form backed by the existing Authkit login endpoint and session middleware. It
creates isolated synthetic accounts/clients, ephemeral signing/encryption keys
and a self-signed HTTPS endpoint. No production credentials or hosted
certification account are required. This exercises protocol HTTPS transport;
it does not establish public certificate-chain trust for a production domain.

The Basic clients explicitly allow the legacy confidential code flow without
PKCE. Separate standard PKCE modules exercise public and confidential S256; the
default client policy remains mandatory PKCE. The `oidf-results` artifact retains
the official module results and browser evidence for seven days, including
warnings, skips and review outcomes. A workflow result alone is not a certificate:
review the full module results and evidence before making conformance claims.
