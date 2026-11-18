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

The `OIDC conformance (transport fix)` workflow runs the OpenID Foundation suite
`release-v5.3.4` (source revision `23353b36957d6466010de767c812d2c91ed37638`)
with the request-builder correction described below and its unmodified official
Python runner. It runs Config OP, Basic OP and Form Post Basic
OP with static registration against the actual Goravel/Authkit integration and
PostgreSQL. The workflow builds the suite from the pinned official source plus one recorded
transport correction; all suite/host builds and verification run in CI.

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

## Interpreting results

The official runner's `--expected-failures-file` option is used only for the
warnings listed in `.ci/oidf/expected-warnings.json`: the SDK's additional
registered JWT `client_id` claim, unavailable optional profile attributes,
undefined ACR classes and the unsupported optional `claims` parameter. No
`failure` outcome is accepted by this file. Package tests assert the ID token's
allowed claim set. `email_verified=false` is returned explicitly.

`.ci/oidf/expected-skips.json` documents four optional cases: address, phone,
all standard scopes (which requires both address and phone), and unsigned
Request Objects. The complete plans still run; the suite decides whether these
modules are applicable from discovery and protocol responses. New warnings,
failures and unexpected skips fail CI. The four browser-evidence cases retain
the suite's `REVIEW` result and include the actual page source in the signed
export; they are not relabeled `PASSED`.

### Known upstream Form Post result in suite 5.3.4

[Verification run](https://github.com/Freshost/goravel-authkit/actions/runs/44335598245)
completed Config OP with 0 failures/0 warnings and Basic OP with 0 failures,
5 documented warnings, 4 optional skips and 4 browser-evidence reviews.

The Form Post Basic plan has one failing module:
`oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported`.
Its `response_mode=form_post` appears only inside an unsupported Request Object;
the outer request has no response mode. Authkit returns `request_not_supported`
using the outer request's default query mode. The suite applies Form Post
transport assertions before recognizing the permitted unsupported response,
producing four failure conditions from this single module. The same module
correctly becomes `SKIPPED` in the Basic/query variant.

This is assessed as a suite mismatch for an optional unsupported feature, based
on the actual request and the unmodified suite's
[request builder](https://gitlab.com/openid/conformance-suite/-/blob/release-v5.3.4/src/main/java/net/openid/conformance/condition/client/AbstractBuildRequestObjectRedirectToAuthorizationEndpoint.java)
and [response handler](https://gitlab.com/openid/conformance-suite/-/blob/release-v5.3.4/src/main/java/net/openid/conformance/openid/AbstractOIDCCRequestObjectServerTest.java).
The upstream maintainers have not confirmed this assessment. Evidence is
retained and this failure remains visible in CI. The public PKCE module runs
independently even when another plan fails.

The provider neither parses unsupported JWT request objects nor advertises
algorithms for an unsupported capability. An empty algorithm list is also
inappropriate: [Discovery 4.2](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse)
requires zero-element claims to be omitted. The release conformance gate remains
open until this result is resolved with the suite maintainers or its handling is
explicitly accepted in the release review. No OpenID certification is claimed.

## Request transport correction and release evidence review

The same issue is independently reported in
[OIDF issue 2042](https://gitlab.com/openid/conformance-suite/-/work_items/2042).
Our retained unmodified-suite result above is unchanged. The CI suite now applies
`.ci/oidf/outer-response-mode.patch` to the pinned 5.3.4 source. It keeps an
existing outer `response_mode` parameter when building a Request Object request.
It does not read an inner mode into the outer request, change a provider response,
or weaken any Form Post assertion. The JAR/PAR `includeDuplicates=false` branch
is unchanged. Focused upstream Java tests cover the changed construction and the
unchanged absent/inner-only/JAR cases; all four provider plans run against the
resulting build. The patch and SHA-256 are included in the evidence artifact.
This is a corrected-suite verification, not an unmodified 5.3.4 pass or an OIDF
certification. Remove the patch once an official release includes the correction.

The internal engineering review of the eight `REVIEW` cases in
[the retained verification](https://github.com/Freshost/goravel-authkit/actions/runs/44337214165)
found no behavior gaps:

| Case, in both query and Form Post | Reviewed evidence |
| --- | --- |
| `prompt=login` | A second empty credential form, successful second login/callback and strictly later signed `auth_time`. |
| `max_age=1` | A fresh credential form after the delay; presence, recency and increase of signed `auth_time` all pass the official conditions. |
| Unregistered redirect | HTTP 400 error page at the provider, with no callback to either the registered or supplied URI. |
| Request Object redirect mismatch | HTTP 400 error page with no callback; this is an explicitly allowed alternative in the official test. |

The raw outcomes remain `REVIEW`: they mark browser evidence needing assessment,
not stalled tests. Each case is `FINISHED`, contains the actual page source, and
has no failure or warning conditions. This is an internal code/evidence review;
OIDF certification review remains separate.

Documented warning dispositions do not expand the provider's data model or
assurance claims: unavailable profile attributes are omitted (Core 5.4); `claims`
is optional and unsupported; no ACR class is claimed for arbitrary requested
values; the SDK's extra registered `client_id` claim identifies the client, not
additional user data. The package's explicit ID-token claim-set test guards
against unintended disclosure. Mandatory public S256 and default confidential
PKCE remain unchanged.
