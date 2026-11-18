package feature

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	frameworkhttp "github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/contracts/route"
	testhttp "github.com/goravel/framework/contracts/testing/http"
	"github.com/goravel/framework/facades"
	"github.com/stretchr/testify/suite"
	protocol "github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/freshost/goravel-authkit/models"
	"github.com/freshost/goravel-authkit/oidc"
	"github.com/freshost/goravel-authkit/repositories"
	authroutes "github.com/freshost/goravel-authkit/routes"
	"goravel/tests"
)

type OIDCTestSuite struct {
	suite.Suite
	tests.TestCase
	provider *oidc.Provider
	previous any
	user     models.User
	clientID string
}

func TestOIDCTestSuite(t *testing.T) { suite.Run(t, new(OIDCTestSuite)) }

func (s *OIDCTestSuite) SetupSuite() {
	s.Require().Equal("postgres", facades.Config().GetString("database.default"), "OIDC integration tests require PostgreSQL")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Require().NoError(err)
	jwks, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: key, KeyID: "ci-signing", Algorithm: "RS256", Use: "sig"}}})
	s.Require().NoError(err)
	s.previous = facades.Config().Get("authkit.oidc.provider")
	facades.Config().Add("authkit.oidc.provider", map[string]any{"enabled": true, "guard": "client", "issuer": "https://identity.example/ci-oidc", "login_url": "/login", "signing_key_id": "ci-signing", "signing_keys": string(jwks), "encryption_key_id": "ci-encryption", "encryption_keys": map[string]any{"ci-encryption": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))}, "scopes": []string{"api:read"}})
	for _, migration := range oidc.Migrations() {
		s.Require().NoError(migration.Up())
	}
	s.provider, err = authroutes.NewOIDCProvider()
	s.Require().NoError(err)
	authroutes.RegisterOIDC(facades.Route())
	facades.Route().Prefix("/ci-oidc-api").Middleware(authroutes.ProtectSessionOrOIDC("client", "https://api.example", "api:read")...).Group(func(r route.Router) {
		r.Get("", func(ctx frameworkhttp.Context) frameworkhttp.Response {
			return ctx.Response().Json(200, frameworkhttp.Json{"userId": authroutes.AuthUserID(ctx).String(), "method": authroutes.AuthMethod(ctx)})
		})
	})
}
func (s *OIDCTestSuite) TearDownSuite() { facades.Config().Add("authkit.oidc.provider", s.previous) }
func (s *OIDCTestSuite) SetupTest() {
	hash, err := facades.Hash().Make("password123")
	s.Require().NoError(err)
	s.user = models.User{ID: uuid.New(), Email: "oidc-" + uuid.NewString() + "@test.local", PasswordHash: &hash, Role: "user", PasswordChangedAt: time.Now().UTC().Truncate(time.Microsecond)}
	s.Require().NoError(repositories.NewUsersWithTable("client_users").Create(context.Background(), &s.user))
	s.clientID = "ci-" + uuid.NewString()
	s.Require().NoError(s.provider.Service.RegisterClient(context.Background(), oidc.Client{ID: s.clientID, Name: "CI web application", ApplicationType: "web", AuthMethod: "none", RedirectURIs: models.StringSlice{"https://app.example/callback"}, Scopes: models.StringSlice{"openid", "profile", "offline_access", "api:read"}, Audience: models.StringSlice{"https://api.example"}, AllowRefresh: true, SkipConsent: true}, ""))
}
func (s *OIDCTestSuite) TearDownTest() {
	q := facades.Orm().Query()
	s.NoError(repositories.NewSessionsWithTable("client_auth_sessions").DeleteByUser(context.Background(), s.user.ID))
	_, auditErr := q.Exec("DELETE FROM client_audit_logs WHERE actor_id = ? OR metadata->>'client_id' = ?", s.user.ID, s.clientID)
	s.NoError(auditErr)
	_, err := q.Exec("DELETE FROM authkit_oidc_tokens WHERE grant_id IN (SELECT id FROM authkit_oidc_grants WHERE issuer = ? AND client_id = ?)", s.provider.Issuer(), s.clientID)
	s.NoError(err)
	_, err = q.Exec("DELETE FROM authkit_oidc_requests WHERE issuer = ? AND client_id = ?", s.provider.Issuer(), s.clientID)
	s.NoError(err)
	_, err = q.Exec("DELETE FROM authkit_oidc_grants WHERE issuer = ? AND client_id = ?", s.provider.Issuer(), s.clientID)
	s.NoError(err)
	_, err = q.Exec("DELETE FROM authkit_oidc_clients WHERE issuer = ? AND id = ?", s.provider.Issuer(), s.clientID)
	s.NoError(err)
	_, err = q.Table("client_users").Where("id", s.user.ID).Delete(&models.User{})
	s.NoError(err)
}
func (s *OIDCTestSuite) login() *http.Cookie {
	data, _ := json.Marshal(map[string]string{"email": s.user.Email, "password": "password123"})
	resp, err := s.Http(s.T()).WithHeader("Content-Type", "application/json").Post("/api/client/v1/auth/login", bytes.NewReader(data))
	s.Require().NoError(err)
	resp.AssertOk()
	return cookieNamed(resp, "authkit_demo_session")
}
func (s *OIDCTestSuite) code(cookie *http.Cookie) (string, string) {
	verifier := strings.Repeat("v", 43)
	params := url.Values{"client_id": {s.clientID}, "response_type": {"code"}, "redirect_uri": {"https://app.example/callback"}, "scope": {"openid profile offline_access api:read"}, "state": {"ci-state"}, "nonce": {"ci-nonce"}, "code_challenge": {protocol.NewSHACodeChallenge(verifier)}, "code_challenge_method": {"S256"}}
	resp, err := s.Http(s.T()).WithCookie(cookie).Get("/ci-oidc/authorize?" + params.Encode())
	s.Require().NoError(err)
	resp.AssertFound()
	interaction, err := url.Parse(resp.Headers().Get("Location"))
	s.Require().NoError(err)
	completed, err := s.Http(s.T()).WithCookie(cookie).Get(interaction.RequestURI())
	s.Require().NoError(err)
	completed.AssertFound()
	callback, err := url.Parse(completed.Headers().Get("Location"))
	s.Require().NoError(err)
	s.Require().Equal("ci-state", callback.Query().Get("state"))
	s.Require().NotEmpty(callback.Query().Get("code"), callback.String())
	return callback.Query().Get("code"), verifier
}
func (s *OIDCTestSuite) exchange(code, verifier string) testhttp.Response {
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {s.clientID}, "redirect_uri": {"https://app.example/callback"}, "code": {code}, "code_verifier": {verifier}}
	r, err := s.Http(s.T()).WithHeader("Content-Type", "application/x-www-form-urlencoded").Post("/ci-oidc/oauth/token", strings.NewReader(form.Encode()))
	s.Require().NoError(err)
	return r
}

type ciOIDCTokens struct {
	Access  string `json:"access_token"`
	Refresh string `json:"refresh_token"`
	ID      string `json:"id_token"`
}

func (s *OIDCTestSuite) TestBrowserSSOAPIRefreshAndRevocation() {
	cookie := s.login()
	code, verifier := s.code(cookie)
	response := s.exchange(code, verifier)
	response.AssertOk()
	var first ciOIDCTokens
	s.Require().NoError(response.Bind(&first))
	s.Require().NotEmpty(first.Access)
	s.Require().NotEmpty(first.Refresh)
	api, err := s.Http(s.T()).WithHeader("Authorization", "Bearer "+first.Access).Get("/ci-oidc-api")
	s.Require().NoError(err)
	api.AssertOk()
	api.AssertJson(map[string]any{"userId": s.user.ID.String(), "method": "oidc"})
	invalid, err := s.Http(s.T()).WithCookie(cookie).WithHeader("Authorization", "Bearer invalid").Get("/ci-oidc-api")
	s.Require().NoError(err)
	invalid.AssertUnauthorized()
	form := url.Values{"grant_type": {"refresh_token"}, "client_id": {s.clientID}, "refresh_token": {first.Refresh}}
	rotated, err := s.Http(s.T()).WithHeader("Content-Type", "application/x-www-form-urlencoded").Post("/ci-oidc/oauth/token", strings.NewReader(form.Encode()))
	s.Require().NoError(err)
	rotated.AssertOk()
	var second ciOIDCTokens
	s.Require().NoError(rotated.Bind(&second))
	s.NotEqual(first.Refresh, second.Refresh)
	form = url.Values{"client_id": {s.clientID}, "token": {second.Refresh}, "token_type_hint": {"refresh_token"}}
	revoked, err := s.Http(s.T()).WithHeader("Content-Type", "application/x-www-form-urlencoded").Post("/ci-oidc/revoke", strings.NewReader(form.Encode()))
	s.Require().NoError(err)
	revoked.AssertOk()
	denied, err := s.Http(s.T()).WithHeader("Authorization", "Bearer "+second.Access).Get("/ci-oidc-api")
	s.Require().NoError(err)
	denied.AssertUnauthorized()
}
func (s *OIDCTestSuite) TestPostgresConcurrentRedemptionAndRotation() {
	for _, kind := range []string{"code", "refresh"} {
		cookie := s.login()
		code, verifier := s.code(cookie)
		var initial ciOIDCTokens
		if kind == "refresh" {
			r := s.exchange(code, verifier)
			r.AssertOk()
			s.Require().NoError(r.Bind(&initial))
		}
		type result struct {
			status int
			body   []byte
		}
		results := make(chan result, 2)
		var wg sync.WaitGroup
		for range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				var form url.Values
				if kind == "code" {
					form = url.Values{"grant_type": {"authorization_code"}, "client_id": {s.clientID}, "redirect_uri": {"https://app.example/callback"}, "code": {code}, "code_verifier": {verifier}}
				} else {
					form = url.Values{"grant_type": {"refresh_token"}, "client_id": {s.clientID}, "refresh_token": {initial.Refresh}}
				}
				r := httptest.NewRequest(http.MethodPost, s.provider.Issuer()+"/oauth/token", strings.NewReader(form.Encode()))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				w := httptest.NewRecorder()
				s.provider.ServeHTTP(w, r)
				results <- result{status: w.Code, body: bytes.Clone(w.Body.Bytes())}
			}()
		}
		wg.Wait()
		close(results)
		var statuses []int
		var winner ciOIDCTokens
		for result := range results {
			statuses = append(statuses, result.status)
			if result.status == 200 {
				s.Require().NoError(json.Unmarshal(result.body, &winner))
			}
		}
		slices.Sort(statuses)
		s.Equal([]int{200, 400}, statuses, kind)
		_, err := s.provider.ResolveAccessToken(context.Background(), winner.Access, "https://api.example")
		s.ErrorIs(err, oidc.ErrInvalidGrant)
		form := url.Values{"grant_type": {"refresh_token"}, "client_id": {s.clientID}, "refresh_token": {winner.Refresh}}
		r := httptest.NewRequest(http.MethodPost, s.provider.Issuer()+"/oauth/token", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		s.provider.ServeHTTP(w, r)
		s.Equal(400, w.Code)
	}
}
func (s *OIDCTestSuite) TestPasswordChangeInvalidatesOriginalRefreshGrant() {
	cookie := s.login()
	code, v := s.code(cookie)
	r := s.exchange(code, v)
	r.AssertOk()
	var out ciOIDCTokens
	s.Require().NoError(r.Bind(&out))
	users := repositories.NewUsersWithTable("client_users")
	previous, err := users.FindByID(context.Background(), s.user.ID)
	s.Require().NoError(err)
	s.Require().NotNil(previous)
	// Force an identical requested epoch; the repository must still advance it.
	s.Require().NoError(users.UpdatePassword(context.Background(), s.user.ID, *s.user.PasswordHash, previous.PasswordChangedAt))
	updated, err := users.FindByID(context.Background(), s.user.ID)
	s.Require().NoError(err)
	s.Require().NotNil(updated)
	s.Require().True(updated.PasswordChangedAt.After(previous.PasswordChangedAt))
	_, err = s.provider.ResolveAccessToken(context.Background(), out.Access, "https://api.example")
	s.ErrorIs(err, oidc.ErrInvalidGrant)
	form := url.Values{"grant_type": {"refresh_token"}, "client_id": {s.clientID}, "refresh_token": {out.Refresh}}
	r, err = s.Http(s.T()).WithHeader("Content-Type", "application/x-www-form-urlencoded").Post("/ci-oidc/oauth/token", strings.NewReader(form.Encode()))
	s.Require().NoError(err)
	r.AssertBadRequest()
	r.AssertJson(map[string]any{"error": "invalid_grant"})
}
func (s *OIDCTestSuite) TestTerminatedSessionCannotManageConnections() {
	cookie := s.login()
	s.Require().NoError(repositories.NewSessionsWithTable("client_auth_sessions").DeleteByUser(context.Background(), s.user.ID))
	r, err := s.Http(s.T()).WithCookie(cookie).Get("/api/client/v1/auth/oidc/connections")
	s.Require().NoError(err)
	r.AssertUnauthorized()
}

func (s *OIDCTestSuite) TestRemoteTerminationProtectsHostOwnedRoutes() {
	for _, path := range []string{"/api/client/v1/portal/whoami", "/api/client/v1/either/whoami", "/ci-oidc-api"} {
		cookie := s.login()
		allowed, err := s.Http(s.T()).WithCookie(cookie).Get(path)
		s.Require().NoError(err)
		allowed.AssertOk()
		s.Require().NoError(repositories.NewSessionsWithTable("client_auth_sessions", "client_remember_tokens").DeleteByUser(context.Background(), s.user.ID))
		denied, err := s.Http(s.T()).WithCookie(cookie).Get(path)
		s.Require().NoError(err)
		denied.AssertUnauthorized()
	}
}

func (s *OIDCTestSuite) TestConsentLookupAndPruneUseLiveGrantWithoutLeakingRequests() {
	cookie := s.login()
	code, verifier := s.code(cookie)
	s.exchange(code, verifier).AssertOk()
	store := oidc.NewStore(s.provider.Issuer())
	user, err := repositories.NewUsersWithTable("client_users").FindByID(context.Background(), s.user.ID)
	s.Require().NoError(err)
	// Thousands of unrelated grants must not be loaded to find a matching consent.
	allowed, err := store.HasConsent(context.Background(), user.ID, s.clientID, 1, user.PasswordChangedAt, user.TwoFactorCredentialStamp(), []string{"openid"}, time.Now())
	s.Require().NoError(err)
	s.True(allowed)
	allowed, err = store.HasConsent(context.Background(), user.ID, s.clientID, 1, user.PasswordChangedAt, user.TwoFactorCredentialStamp(), []string{"not-granted"}, time.Now())
	s.Require().NoError(err)
	s.False(allowed)
	// A short-lived grant can precede its request's expiry under supported settings.
	before := time.Now().Add(-31 * 24 * time.Hour).UTC()
	_, err = facades.Orm().Query().Exec("UPDATE authkit_oidc_grants SET expires_at = ? WHERE issuer = ? AND client_id = ?", before.Add(-time.Minute), s.provider.Issuer(), s.clientID)
	s.Require().NoError(err)
	_, err = facades.Orm().Query().Exec("UPDATE authkit_oidc_requests SET expires_at = ? WHERE issuer = ? AND client_id = ?", before.Add(time.Minute), s.provider.Issuer(), s.clientID)
	s.Require().NoError(err)
	s.Require().NoError(store.Prune(context.Background(), before))
	count, err := facades.Orm().Query().Table("authkit_oidc_requests").Where("issuer", s.provider.Issuer()).Where("client_id", s.clientID).Count()
	s.Require().NoError(err)
	s.Zero(count)
	s.Require().NoError(store.Prune(context.Background(), before.Add(time.Hour)))
}
