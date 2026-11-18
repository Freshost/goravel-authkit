# OIDC conformance verification

The supported provider profile is documented in [OIDC](oidc.md). Compatibility
must be established for the integrated Authkit provider, not inferred from its
dependency. OpenID certification is a separate process; no certification is
claimed by adding the SDK.

Before a provider release:

1. Run the package test, race and vet gates and PostgreSQL demo feature tests in
   CI. This includes code/refresh concurrency, client/issuer binding, account
   invalidation, consent, PKCE and key rotation.
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
