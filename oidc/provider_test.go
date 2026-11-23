package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/freshost/goravel-authkit/models"
	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	protocol "github.com/zitadel/oidc/v3/pkg/oidc"
)

// This transactional fake exercises service policy. PostgreSQL locking and
// transport integration are separately covered by the demo feature suite.
type memoryData struct {
	clients  map[string]Client
	requests map[string]authorization
	grants   map[string]Connection
	tokens   map[string]token
}
type memoryStore struct {
	mu          *sync.Mutex
	data        *memoryData
	transaction bool
}

func newMemoryStore() *memoryStore {
	return &memoryStore{mu: &sync.Mutex{}, data: &memoryData{clients: map[string]Client{}, requests: map[string]authorization{}, grants: map[string]Connection{}, tokens: map[string]token{}}}
}
func (s *memoryStore) locked() func() {
	if s.transaction {
		return func() {}
	}
	s.mu.Lock()
	return s.mu.Unlock
}
func (s *memoryStore) Transaction(ctx context.Context, fn func(Store) error) error {
	defer s.locked()()
	d := &memoryData{clients: map[string]Client{}, requests: map[string]authorization{}, grants: map[string]Connection{}, tokens: map[string]token{}}
	for k, v := range s.data.clients {
		d.clients[k] = v
	}
	for k, v := range s.data.requests {
		d.requests[k] = v
	}
	for k, v := range s.data.grants {
		d.grants[k] = v
	}
	for k, v := range s.data.tokens {
		d.tokens[k] = v
	}
	tx := &memoryStore{mu: s.mu, data: d, transaction: true}
	if err := fn(tx); err != nil {
		return err
	}
	s.data = d
	return nil
}
func (s *memoryStore) Client(_ context.Context, id string, _ bool) (*Client, error) {
	defer s.locked()()
	v, ok := s.data.clients[id]
	if !ok {
		return nil, nil
	}
	return &v, nil
}
func (s *memoryStore) SaveClient(_ context.Context, v *Client) error {
	defer s.locked()()
	s.data.clients[v.ID] = *v
	return nil
}
func (s *memoryStore) CreateClient(_ context.Context, v *Client) error {
	defer s.locked()()
	if _, exists := s.data.clients[v.ID]; exists {
		return errors.New("duplicate client")
	}
	s.data.clients[v.ID] = *v
	return nil
}
func (s *memoryStore) Request(_ context.Context, id string, _ bool) (*authorization, error) {
	defer s.locked()()
	v, ok := s.data.requests[id]
	if !ok {
		return nil, nil
	}
	return &v, nil
}
func (s *memoryStore) RequestByCode(_ context.Context, hash string) (*authorization, error) {
	defer s.locked()()
	for _, v := range s.data.requests {
		if v.CodeHash != nil && *v.CodeHash == hash {
			return &v, nil
		}
	}
	return nil, nil
}
func (s *memoryStore) SaveRequest(_ context.Context, v *authorization) error {
	defer s.locked()()
	s.data.requests[v.ID] = *v
	return nil
}
func (s *memoryStore) Grant(_ context.Context, id string, _ bool) (*Connection, error) {
	defer s.locked()()
	v, ok := s.data.grants[id]
	if !ok {
		return nil, nil
	}
	return &v, nil
}
func (s *memoryStore) SaveGrant(_ context.Context, v *Connection) error {
	defer s.locked()()
	s.data.grants[v.ID] = *v
	return nil
}
func (s *memoryStore) Token(_ context.Context, id string, _ bool) (*token, error) {
	defer s.locked()()
	v, ok := s.data.tokens[id]
	if !ok {
		return nil, nil
	}
	return &v, nil
}
func (s *memoryStore) Refresh(_ context.Context, hash string, _ bool) (*token, error) {
	defer s.locked()()
	for _, v := range s.data.tokens {
		if v.Kind == "refresh" && v.Hash != nil && *v.Hash == hash {
			return &v, nil
		}
	}
	return nil, nil
}
func (s *memoryStore) SaveToken(_ context.Context, v *token) error {
	defer s.locked()()
	s.data.tokens[v.ID] = *v
	return nil
}
func (s *memoryStore) Connections(_ context.Context, id uuid.UUID) ([]Connection, error) {
	defer s.locked()()
	var out []Connection
	for _, v := range s.data.grants {
		if v.UserID == id && v.RevokedAt == nil {
			out = append(out, v)
		}
	}
	return out, nil
}
func (s *memoryStore) HasConsent(_ context.Context, user uuid.UUID, client string, version int64, stamp time.Time, mfa string, scopes []string, now time.Time) (bool, error) {
	defer s.locked()()
	for _, g := range s.data.grants {
		if g.UserID == user && g.ClientID == client && g.ClientVersion == version && g.CredentialStamp.Equal(stamp) && g.TwoFactorStamp == mfa && g.RevokedAt == nil && now.Before(g.ExpiresAt) && subset(scopes, g.Scopes) {
			return true, nil
		}
	}
	return false, nil
}
func (s *memoryStore) RevokeUser(_ context.Context, id uuid.UUID, now time.Time) error {
	defer s.locked()()
	for k, v := range s.data.grants {
		if v.UserID == id {
			v.RevokedAt = &now
			s.data.grants[k] = v
		}
	}
	return nil
}
func (s *memoryStore) Prune(context.Context, time.Time) error { return nil }

type testUsers struct {
	user models.User
	err  error
}

func (u *testUsers) FindByID(_ context.Context, id uuid.UUID) (*models.User, error) {
	if u.err != nil {
		return nil, u.err
	}
	if id != u.user.ID {
		return nil, nil
	}
	v := u.user
	return &v, nil
}

type testHasher struct{}

func (testHasher) Make(v string) (string, error) { return digest(v), nil }
func (testHasher) Check(v, h string) bool        { return digest(v) == h }

var fixtureKey struct {
	sync.Once
	key *rsa.PrivateKey
	err error
}

func testProvider(t *testing.T) (*Provider, Browser, *testUsers) {
	t.Helper()
	fixtureKey.Do(func() { fixtureKey.key, fixtureKey.err = rsa.GenerateKey(rand.Reader, 2048) })
	require.NoError(t, fixtureKey.err)
	jwk := jose.JSONWebKey{Key: fixtureKey.key, KeyID: "signing-1", Algorithm: "RS256", Use: "sig"}
	keys, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
	require.NoError(t, err)
	c := Config{Enabled: true, Issuer: "https://identity.example/oidc", Guard: "users", LoginURL: "/login", SigningKeyID: "signing-1", SigningKeysJSON: string(keys), EncryptionKeyID: "encryption-1", EncryptionKeys: map[string]string{"encryption-1": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))}, Scopes: []string{"api:read", "api:write"}, AllowedOrigins: []string{"https://app.example"}}
	u := &testUsers{user: models.User{ID: uuid.New(), Email: "user@example.test", PasswordChangedAt: time.Now().UTC().Add(-time.Hour)}}
	p, err := New(c, newMemoryStore(), u, testHasher{})
	require.NoError(t, err)
	b := Browser{Binding: "browser-secret", UserID: u.user.ID, CredentialStamp: u.user.PasswordChangedAt, AuthTime: time.Now().UTC().Add(-time.Minute), AuthEvent: "login-event", AMR: []string{"pwd"}, TwoFactorStamp: u.user.TwoFactorCredentialStamp()}
	client := Client{ID: "public", Name: "Example application", ApplicationType: "web", AuthMethod: "none", RedirectURIs: models.StringSlice{"https://app.example/callback"}, Scopes: models.StringSlice{"openid", "profile", "email", "offline_access", "api:read", "api:write"}, Audience: models.StringSlice{"https://api.example"}, AllowRefresh: true, SkipConsent: true}
	require.NoError(t, p.Service.RegisterClient(context.Background(), client, ""))
	return p, b, u
}

func request(p *Provider, b Browser, method, path string, form url.Values) *httptest.ResponseRecorder {
	var body *strings.Reader
	if form == nil {
		body = strings.NewReader("")
	} else {
		body = strings.NewReader(form.Encode())
	}
	r := httptest.NewRequest(method, p.Issuer()+path, body)
	r = r.WithContext(WithBrowser(r.Context(), b))
	if method == http.MethodPost {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	return w
}
func authorize(t *testing.T, p *Provider, b Browser, extra url.Values) (string, string) {
	t.Helper()
	verifier := strings.Repeat("v", 43)
	form := url.Values{"client_id": {"public"}, "redirect_uri": {"https://app.example/callback"}, "response_type": {"code"}, "scope": {"openid profile email offline_access api:read api:write"}, "state": {"opaque-state"}, "nonce": {"request-nonce"}, "code_challenge": {protocol.NewSHACodeChallenge(verifier)}, "code_challenge_method": {"S256"}}
	for k, v := range extra {
		form[k] = v
	}
	w := request(p, b, http.MethodGet, "/authorize?"+form.Encode(), nil)
	require.Equal(t, 302, w.Code, w.Body.String())
	location, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	require.NotEmpty(t, location.Query().Get("id"), location.String())
	return location.Query().Get("id"), verifier
}
func authorizeCode(t *testing.T, p *Provider, b Browser, extra url.Values) (string, string) {
	t.Helper()
	id, verifier := authorize(t, p, b, extra)
	w := request(p, b, http.MethodGet, "/interaction?id="+id, nil)
	require.Equal(t, 302, w.Code, w.Body.String())
	location, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "opaque-state", location.Query().Get("state"))
	code := location.Query().Get("code")
	require.NotEmpty(t, code, location.String())
	return code, verifier
}
func exchange(p *Provider, code, verifier, client string) *httptest.ResponseRecorder {
	return request(p, Browser{}, http.MethodPost, "/oauth/token", url.Values{"grant_type": {"authorization_code"}, "client_id": {client}, "redirect_uri": {"https://app.example/callback"}, "code": {code}, "code_verifier": {verifier}})
}
func refresh(p *Provider, value, client, scope string) *httptest.ResponseRecorder {
	v := url.Values{"grant_type": {"refresh_token"}, "client_id": {client}, "refresh_token": {value}}
	if scope != "" {
		v.Set("scope", scope)
	}
	return request(p, Browser{}, http.MethodPost, "/oauth/token", v)
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`
	Error        string `json:"error"`
}

func tokens(t *testing.T, w *httptest.ResponseRecorder) tokenResponse {
	t.Helper()
	require.Equal(t, 200, w.Code, w.Body.String())
	var v tokenResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &v))
	require.NotEmpty(t, v.AccessToken)
	return v
}

func TestCodeFlowDiscoveryAndClaims(t *testing.T) {
	p, b, u := testProvider(t)
	code, verifier := authorizeCode(t, p, b, nil)
	out := tokens(t, exchange(p, code, verifier, "public"))
	require.NotEmpty(t, out.RefreshToken)
	signed, err := jose.ParseSigned(out.IDToken, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)
	payload, err := signed.Verify(&fixtureKey.key.PublicKey)
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims))
	require.Equal(t, p.Issuer(), claims["iss"])
	require.Equal(t, u.user.ID.String(), claims["sub"])
	require.Equal(t, "request-nonce", claims["nonce"])
	require.Equal(t, "public", claims["azp"])
	// Additional SDK claims must never accidentally disclose profile or secrets.
	for claim := range claims {
		require.Contains(t, []string{"iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "amr", "azp", "client_id", "at_hash", "c_hash"}, claim)
	}
	identity, err := p.ResolveAccessToken(context.Background(), out.AccessToken, "https://api.example", "api:read")
	require.NoError(t, err)
	require.Equal(t, u.user.ID, identity.UserID)
	_, err = p.ResolveAccessToken(context.Background(), out.IDToken, "https://api.example")
	require.ErrorIs(t, err, ErrInvalidGrant)
	_, err = p.ResolveAccessToken(context.Background(), out.AccessToken, "https://other.example")
	require.ErrorIs(t, err, ErrInvalidGrant)
	d := request(p, Browser{}, http.MethodGet, "/.well-known/openid-configuration", nil)
	var metadata map[string]any
	require.NoError(t, json.Unmarshal(d.Body.Bytes(), &metadata))
	require.Equal(t, []any{"code"}, metadata["response_types_supported"])
	require.NotContains(t, metadata, "end_session_endpoint")
	require.NotContains(t, metadata, "device_authorization_endpoint")
	require.NotContains(t, metadata, "introspection_endpoint")
	require.Equal(t, 404, request(p, b, http.MethodGet, "/authorize/callback?id=anything", nil).Code)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, p.Issuer()+"/userinfo", nil)
	r.Header.Set("Authorization", "Bearer "+out.AccessToken)
	p.ServeHTTP(w, r)
	require.Equal(t, 200, w.Code, w.Body.String())
	var info map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &info))
	require.Equal(t, u.user.Email, info["email"])
	require.Equal(t, false, info["email_verified"])
}

func TestInvalidPKCEDoesNotConsumeCode(t *testing.T) {
	p, b, _ := testProvider(t)
	code, v := authorizeCode(t, p, b, nil)
	for _, bad := range []string{"x", strings.Repeat("x", 43), strings.Repeat("!", 43), strings.Repeat("x", 129)} {
		w := exchange(p, code, bad, "public")
		require.Equal(t, 400, w.Code, w.Body.String())
	}
	tokens(t, exchange(p, code, v, "public"))
}

func TestRefreshRotationAndReplayRevokesConnection(t *testing.T) {
	p, b, _ := testProvider(t)
	code, v := authorizeCode(t, p, b, nil)
	first := tokens(t, exchange(p, code, v, "public"))
	second := tokens(t, refresh(p, first.RefreshToken, "public", "openid api:read"))
	require.NotEqual(t, first.RefreshToken, second.RefreshToken)
	wide := refresh(p, second.RefreshToken, "public", "openid api:write")
	require.Equal(t, 400, wide.Code, wide.Body.String())
	replay := refresh(p, first.RefreshToken, "public", "")
	require.Equal(t, 400, replay.Code, replay.Body.String())
	_, err := p.ResolveAccessToken(context.Background(), second.AccessToken, "https://api.example")
	require.ErrorIs(t, err, ErrInvalidGrant)
	require.Equal(t, 400, refresh(p, second.RefreshToken, "public", "").Code)
}

func TestConcurrentCodeAndRefresh(t *testing.T) {
	for _, kind := range []string{"code", "refresh"} {
		t.Run(kind, func(t *testing.T) {
			p, b, _ := testProvider(t)
			code, v := authorizeCode(t, p, b, nil)
			var initial tokenResponse
			if kind == "refresh" {
				initial = tokens(t, exchange(p, code, v, "public"))
			}
			results := make(chan *httptest.ResponseRecorder, 2)
			var wg sync.WaitGroup
			for range 2 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if kind == "code" {
						results <- exchange(p, code, v, "public")
					} else {
						results <- refresh(p, initial.RefreshToken, "public", "")
					}
				}()
			}
			wg.Wait()
			close(results)
			var statuses []int
			for w := range results {
				statuses = append(statuses, w.Code)
			}
			slices.Sort(statuses)
			require.Equal(t, []int{200, 400}, statuses)
		})
	}
}

func TestClientBindingAndRevocation(t *testing.T) {
	p, b, _ := testProvider(t)
	client, _ := p.Service.store.Client(context.Background(), "public", false)
	client.ID = "other"
	require.NoError(t, p.Service.RegisterClient(context.Background(), *client, ""))
	code, v := authorizeCode(t, p, b, nil)
	require.Equal(t, 400, exchange(p, code, v, "other").Code)
	out := tokens(t, exchange(p, code, v, "public"))
	require.Equal(t, 400, refresh(p, out.RefreshToken, "other", "").Code)
	identity, err := p.ResolveAccessToken(context.Background(), out.AccessToken, "https://api.example")
	require.NoError(t, err)
	// An internal token ID is not a credential and cannot authorize revocation.
	plain, err := p.protocol.Crypto().Decrypt(out.AccessToken)
	require.NoError(t, err)
	id := strings.Split(plain, ":")[0]
	require.Equal(t, 200, request(p, Browser{}, http.MethodPost, "/revoke", url.Values{"client_id": {"public"}, "token": {id}}).Code)
	_, err = p.ResolveAccessToken(context.Background(), out.AccessToken, "https://api.example")
	require.NoError(t, err)
	require.NoError(t, p.Service.RevokeConnection(context.Background(), identity.UserID, identity.ConnectionID))
	_, err = p.ResolveAccessToken(context.Background(), out.AccessToken, "https://api.example")
	require.ErrorIs(t, err, ErrInvalidGrant)
}

func TestLiveAccountAndClientInvalidation(t *testing.T) {
	for _, change := range []string{"password", "disable", "delete", "two-factor", "client"} {
		t.Run(change, func(t *testing.T) {
			p, b, u := testProvider(t)
			code, v := authorizeCode(t, p, b, nil)
			out := tokens(t, exchange(p, code, v, "public"))
			switch change {
			case "password":
				u.user.PasswordChangedAt = time.Now().UTC()
			case "disable":
				now := time.Now().UTC()
				u.user.DisabledAt = &now
			case "delete":
				u.user.ID = uuid.New()
			case "two-factor":
				secret := "encrypted-secret"
				now := time.Now().UTC()
				u.user.TwoFactorSecret = &secret
				u.user.TwoFactorConfirmedAt = &now
			case "client":
				require.NoError(t, p.Service.DisableClient(context.Background(), "public"))
			}
			_, err := p.ResolveAccessToken(context.Background(), out.AccessToken, "https://api.example")
			require.ErrorIs(t, err, ErrInvalidGrant)
			require.NotEqual(t, 200, refresh(p, out.RefreshToken, "public", "").Code)
		})
	}
}

func TestInteractionBindingFreshnessAndMFA(t *testing.T) {
	p, b, u := testProvider(t)
	id, _ := authorize(t, p, b, url.Values{"prompt": {"login"}})
	result, err := p.Service.interaction(context.Background(), id, b, false, "", "")
	require.NoError(t, err)
	require.Equal(t, "login", result.next)
	b.AuthEvent = "new-event"
	result, err = p.Service.interaction(context.Background(), id, b, false, "", "")
	require.NoError(t, err)
	require.Equal(t, "authorized", result.next)
	other := b
	other.Binding = "another-browser"
	_, err = p.Service.interaction(context.Background(), id, other, false, "", "")
	require.ErrorIs(t, err, ErrValidation)
	id, _ = authorize(t, p, b, url.Values{"prompt": {"none"}})
	b.Impersonating = true
	_, err = p.Service.interaction(context.Background(), id, b, false, "", "")
	require.ErrorIs(t, err, ErrForbidden)
	b.Impersonating = false
	secret := "new-mfa-credential"
	now := time.Now().UTC()
	u.user.TwoFactorSecret = &secret
	u.user.TwoFactorConfirmedAt = &now
	b.AMR = []string{"pwd", "mfa", "otp"}
	_, err = p.Service.interaction(context.Background(), id, b, false, "", "")
	require.ErrorIs(t, err, ErrLoginRequired)
}

func TestConsentCannotChangeAccountOrAuthentication(t *testing.T) {
	p, b, _ := testProvider(t)
	id, _ := authorize(t, p, b, url.Values{"prompt": {"consent"}})
	result, err := p.Service.interaction(context.Background(), id, b, false, "", "")
	require.NoError(t, err)
	require.Equal(t, "consent", result.next)
	require.NotEmpty(t, result.csrf)
	changed := b
	changed.AuthEvent = "changed-account-event"
	_, err = p.Service.interaction(context.Background(), id, changed, true, "approve", result.csrf)
	require.ErrorIs(t, err, ErrForbidden)
	_, err = p.Service.interaction(context.Background(), id, b, true, "approve", "wrong")
	require.ErrorIs(t, err, ErrForbidden)
	approved, err := p.Service.interaction(context.Background(), id, b, true, "approve", result.csrf)
	require.NoError(t, err)
	require.Equal(t, "authorized", approved.next)
}

func TestConsentTemplates(t *testing.T) {
	const custom = `<link rel="stylesheet" href="/assets/oidc-consent.css">
<h1>Connect to {{.ClientName}}</h1><p>{{.Account}}</p>
<ul>{{range .Scopes}}<li>{{.}}</li>{{end}}</ul>
<form method="post" action="{{.Action}}">
<input type="hidden" name="id" value="{{.RequestID}}">
<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
<button name="decision" value="approve">Connect</button>
<button name="decision" value="deny">Cancel</button>
</form>`
	for _, tc := range []struct {
		name, source, heading, scope string
	}{
		{"default", "", "<h1>Authorize Example &lt;app&gt;</h1>", "Requested scopes: openid"},
		{"custom", custom, "<h1>Connect to Example &lt;app&gt;</h1>", "<li>openid</li>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture, browser, users := testProvider(t)
			cfg := fixture.Service.config
			cfg.ConsentTemplate = tc.source
			p, err := New(cfg, fixture.Service.store, users, testHasher{})
			require.NoError(t, err)
			client, err := p.Service.store.Client(t.Context(), "public", false)
			require.NoError(t, err)
			client.Name = "Example <app>"
			require.NoError(t, p.Service.RegisterClient(t.Context(), *client, ""))

			for _, decision := range []string{"deny", "approve"} {
				id, verifier := authorize(t, p, browser, url.Values{"prompt": {"consent"}, "scope": {"openid profile"}})
				page := request(p, browser, http.MethodGet, "/interaction?id="+id, nil)
				fields := formFields(t, page)
				require.Equal(t, id, fields.Get("id"))
				require.NotEmpty(t, fields.Get("csrf_token"))
				require.Contains(t, page.Body.String(), tc.heading)
				require.Contains(t, page.Body.String(), tc.scope)
				require.Contains(t, page.Body.String(), users.user.Email)
				require.Contains(t, page.Body.String(), `method="post" action="`+p.Issuer()+`/interaction"`)
				require.Contains(t, page.Body.String(), `name="decision" value="`+decision+`"`)
				csp := "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
				if tc.source != "" {
					csp += "; style-src 'self'"
					require.Contains(t, page.Body.String(), `href="/assets/oidc-consent.css"`)
				}
				require.Equal(t, csp, page.Header().Get("Content-Security-Policy"))
				require.Equal(t, "DENY", page.Header().Get("X-Frame-Options"))
				require.Equal(t, "no-store", page.Header().Get("Cache-Control"))

				fields.Set("decision", decision)
				other := browser
				other.Binding = "different-browser"
				require.Equal(t, 400, request(p, other, http.MethodPost, "/interaction", fields).Code)
				badCSRF := url.Values{"decision": {"approve"}, "id": {id}, "csrf_token": {"invalid"}}
				require.Equal(t, 400, request(p, browser, http.MethodPost, "/interaction", badCSRF).Code)

				res := request(p, browser, http.MethodPost, "/interaction", fields)
				require.Equal(t, 302, res.Code)
				callback, err := url.Parse(res.Header().Get("Location"))
				require.NoError(t, err)
				require.Equal(t, "opaque-state", callback.Query().Get("state"))
				code := callback.Query().Get("code")
				if decision == "deny" {
					require.Equal(t, "access_denied", callback.Query().Get("error"))
					require.Empty(t, code)
					continue
				}
				require.NotEmpty(t, code)
				require.Equal(t, 400, exchange(p, code, strings.Repeat("w", 43), "public").Code)
				tokens(t, exchange(p, code, verifier, "public"))
			}
		})
	}
}

func TestInvalidConsentTemplate(t *testing.T) {
	p, b, users := testProvider(t)
	cfg := p.Service.config
	cfg.ConsentTemplate = "{{if}}"
	_, err := New(cfg, p.Service.store, users, testHasher{})
	require.ErrorIs(t, err, ErrValidation)

	cfg.ConsentTemplate = "<p>Partial page</p>{{.UnknownField}}"
	custom, err := New(cfg, p.Service.store, users, testHasher{})
	require.NoError(t, err)
	id, _ := authorize(t, custom, b, url.Values{"prompt": {"consent"}})
	page := request(custom, b, http.MethodGet, "/interaction?id="+id, nil)
	require.Equal(t, 500, page.Code)
	require.Equal(t, "Unable to render the consent page\n", page.Body.String())
}

func TestBackendErrorsFailClosed(t *testing.T) {
	p, b, u := testProvider(t)
	code, v := authorizeCode(t, p, b, nil)
	out := tokens(t, exchange(p, code, v, "public"))
	u.err = errors.New("database unavailable")
	_, err := p.ResolveAccessToken(context.Background(), out.AccessToken, "https://api.example")
	require.Error(t, err)
	require.False(t, IsAuthenticationError(err))
	w := refresh(p, out.RefreshToken, "public", "")
	require.Equal(t, 500, w.Code)
	require.NotContains(t, w.Body.String(), "database unavailable")
}

func TestDisabledProviderNeedsNoConfiguration(t *testing.T) {
	p, err := New(Config{}, nil, nil, nil)
	require.NoError(t, err)
	require.Nil(t, p)
}

func TestConfidentialClientRequiresHTTPBasic(t *testing.T) {
	p, b, _ := testProvider(t)
	client, err := p.Service.store.Client(context.Background(), "public", false)
	require.NoError(t, err)
	client.ID = "confidential"
	client.AuthMethod = "client_secret_basic"
	secret := strings.Repeat("s", 43)
	require.NoError(t, p.Service.RegisterClient(context.Background(), *client, secret))
	code, v := authorizeCode(t, p, b, url.Values{"client_id": {"confidential"}})
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {"confidential"}, "redirect_uri": {"https://app.example/callback"}, "code": {code}, "code_verifier": {v}, "client_secret": {secret}}
	require.Equal(t, 401, request(p, Browser{}, http.MethodPost, "/oauth/token", form).Code)
	form.Del("client_secret")
	require.Equal(t, 401, request(p, Browser{}, http.MethodPost, "/oauth/token", form).Code)
	r := httptest.NewRequest(http.MethodPost, p.Issuer()+"/oauth/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth("confidential", secret)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	tokens(t, w)
}

func TestPublicClientCORSAndNativeRedirectMatching(t *testing.T) {
	p, _, _ := testProvider(t)
	for _, origin := range []string{"https://app.example", "https://untrusted.example"} {
		r := httptest.NewRequest(http.MethodOptions, p.Issuer()+"/oauth/token", nil)
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		p.ServeHTTP(w, r)
		if origin == "https://app.example" {
			require.Equal(t, 204, w.Code)
			require.Equal(t, origin, w.Header().Get("Access-Control-Allow-Origin"))
		} else {
			require.Equal(t, 403, w.Code)
		}
		require.Empty(t, w.Header().Get("Access-Control-Allow-Credentials"))
	}
	require.True(t, registeredRedirect([]string{"http://127.0.0.1/callback"}, "http://127.0.0.1:53193/callback", true))
	require.False(t, registeredRedirect([]string{"http://127.0.0.1/callback"}, "http://localhost:53193/callback", true))
	require.False(t, registeredRedirect([]string{"http://127.0.0.1/callback"}, "http://127.0.0.1:53193/other", true))
	require.False(t, registeredRedirect([]string{"https://app.example/callback"}, "https://app.example/callback/extra", false))
}

func TestSigningAndEncryptionKeyRotation(t *testing.T) {
	p, b, u := testProvider(t)
	code, v := authorizeCode(t, p, b, nil)
	out := tokens(t, exchange(p, code, v, "public"))
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	keys, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &fixtureKey.key.PublicKey, KeyID: "signing-1", Algorithm: "RS256", Use: "sig"}, {Key: newKey, KeyID: "signing-2", Algorithm: "RS256", Use: "sig"}}})
	require.NoError(t, err)
	c := p.Service.config
	c.SigningKeysJSON = string(keys)
	c.SigningKeyID = "signing-2"
	c.EncryptionKeys = map[string]string{"encryption-1": c.EncryptionKeys["encryption-1"], "encryption-2": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("n", 32)))}
	c.EncryptionKeyID = "encryption-2"
	rotated, err := New(c, p.Service.store, u, testHasher{})
	require.NoError(t, err)
	_, err = rotated.ResolveAccessToken(context.Background(), out.AccessToken, "https://api.example")
	require.NoError(t, err)
	current := tokens(t, refresh(rotated, out.RefreshToken, "public", ""))
	signed, err := jose.ParseSigned(current.IDToken, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)
	_, err = signed.Verify(&newKey.PublicKey)
	require.NoError(t, err)
	w := request(rotated, Browser{}, http.MethodGet, "/keys", nil)
	var published jose.JSONWebKeySet
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &published))
	require.Len(t, published.Keys, 2)
	for _, k := range published.Keys {
		require.True(t, k.IsPublic())
	}
}

func formFields(t *testing.T, w *httptest.ResponseRecorder) url.Values {
	t.Helper()
	require.Equal(t, 200, w.Code)
	require.Contains(t, w.Header().Get("Content-Type"), "text/html")
	values := url.Values{}
	for _, match := range regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)">`).FindAllStringSubmatch(w.Body.String(), -1) {
		values.Add(html.UnescapeString(match[1]), html.UnescapeString(match[2]))
	}
	return values
}

func TestFormPostSuccessAndErrorsUseTheSameStandardTransport(t *testing.T) {
	p, b, _ := testProvider(t)
	id, v := authorize(t, p, b, url.Values{"response_mode": {"form_post"}})
	w := request(p, b, http.MethodGet, "/interaction?id="+id, nil)
	fields := formFields(t, w)
	require.NotEmpty(t, fields.Get("code"))
	require.Equal(t, "opaque-state", fields.Get("state"))
	require.Empty(t, fields.Get("error"))
	tokens(t, exchange(p, fields.Get("code"), v, "public"))
	anon := Browser{Binding: "anonymous-browser"}
	id, _ = authorize(t, p, anon, url.Values{"response_mode": {"form_post"}, "prompt": {"none"}})
	w = request(p, anon, http.MethodGet, "/interaction?id="+id, nil)
	fields = formFields(t, w)
	require.Equal(t, "login_required", fields.Get("error"))
	require.Equal(t, "opaque-state", fields.Get("state"))
	require.Empty(t, fields.Get("code"))
	require.Contains(t, w.Header().Get("Content-Security-Policy"), "script-src 'nonce-")
}

type delayedTransactionStore struct {
	Store
	before func()
}

func (s delayedTransactionStore) Transaction(ctx context.Context, fn func(Store) error) error {
	return s.Store.Transaction(ctx, func(tx Store) error { s.before(); return fn(tx) })
}
func TestExpiryIsCheckedAfterWaitingForTransaction(t *testing.T) {
	p, b, _ := testProvider(t)
	code, v := authorizeCode(t, p, b, nil)
	now := time.Now().UTC()
	p.Service.now = func() time.Time { return now }
	store := p.Service.store
	p.Service.store = delayedTransactionStore{Store: store, before: func() { now = now.Add(3 * time.Minute) }}
	w := exchange(p, code, v, "public")
	require.Equal(t, 400, w.Code)
}

func TestClientPolicyCannotChangeBetweenValidationAndPersistence(t *testing.T) {
	p, b, _ := testProvider(t)
	client, err := p.Service.client(context.Background(), "public")
	require.NoError(t, err)
	ctx := context.WithValue(WithBrowser(context.Background(), b), validatedClientKey{}, client.Version)
	client.Name = "Updated application"
	require.NoError(t, p.Service.RegisterClient(context.Background(), *client, ""))
	_, err = p.storage.CreateAuthRequest(ctx, &protocol.AuthRequest{ClientID: "public", RedirectURI: "https://app.example/callback", ResponseType: protocol.ResponseTypeCode, Scopes: protocol.SpaceDelimitedArray{"openid"}, CodeChallenge: protocol.NewSHACodeChallenge(strings.Repeat("v", 43)), CodeChallengeMethod: protocol.CodeChallengeMethodS256}, "")
	require.Error(t, err)
}

func TestConfidentialPKCEOptOutAndAuthenticationBinding(t *testing.T) {
	p, b, _ := testProvider(t)
	ctx := context.Background()
	client, err := p.Service.client(ctx, "public")
	require.NoError(t, err)
	optional := false
	client.RequirePKCE = &optional
	require.ErrorIs(t, p.Service.RegisterClient(ctx, *client, ""), ErrValidation)
	client.ID = "legacy-confidential"
	client.AuthMethod = "client_secret_post"
	secret := strings.Repeat("s", 43)
	require.NoError(t, p.Service.RegisterClient(ctx, *client, secret))
	code, _ := authorizeCode(t, p, b, url.Values{"client_id": {client.ID}, "code_challenge": {""}, "code_challenge_method": {""}})
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {client.ID}, "redirect_uri": {"https://app.example/callback"}, "code": {code}}
	require.Equal(t, 401, request(p, Browser{}, http.MethodPost, "/oauth/token", form).Code)
	r := httptest.NewRequest(http.MethodPost, p.Issuer()+"/oauth/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth(client.ID, secret)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	require.Equal(t, 401, w.Code, "POST clients cannot switch to Basic authentication")
	form.Set("client_secret", secret)
	tokens(t, request(p, Browser{}, http.MethodPost, "/oauth/token", form))
	client.RequirePKCE = nil
	require.NoError(t, p.Service.RegisterClient(ctx, *client, secret))
	w = request(p, b, http.MethodGet, "/authorize?"+url.Values{"client_id": {client.ID}, "response_type": {"code"}, "redirect_uri": {client.RedirectURIs[0]}, "scope": {"openid"}}.Encode(), nil)
	require.Contains(t, w.Header().Get("Location"), "error=invalid_request", "PKCE remains the default")
}

func TestUserinfoBearerChallengesAndBodyTransport(t *testing.T) {
	p, b, _ := testProvider(t)
	code, verifier := authorizeCode(t, p, b, nil)
	out := tokens(t, exchange(p, code, verifier, "public"))
	w := request(p, Browser{}, http.MethodPost, "/userinfo", url.Values{"access_token": {out.AccessToken}})
	require.Equal(t, 200, w.Code)
	w = request(p, Browser{}, http.MethodGet, "/userinfo?access_token="+url.QueryEscape(out.AccessToken), nil)
	require.Equal(t, 400, w.Code)
	require.Contains(t, w.Header().Get("WWW-Authenticate"), "invalid_request")
	require.NoError(t, p.Service.RevokeAll(context.Background(), b.UserID))
	w = request(p, Browser{}, http.MethodPost, "/userinfo", url.Values{"access_token": {out.AccessToken}})
	require.Equal(t, 401, w.Code)
	require.Contains(t, w.Header().Get("WWW-Authenticate"), "invalid_token")
}

// Request Objects are optional. Unsupported JWT content must not select a
// transport, callback or state; errors use only the validated outer request.
func TestUnsupportedRequestObjectUsesOuterResponseMode(t *testing.T) {
	p, b, _ := testProvider(t)
	object := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(`{"response_mode":"form_post","redirect_uri":"https://untrusted.example/callback","state":"inner-state"}`)) + "."
	for _, mode := range []string{"", "form_post"} {
		t.Run(mode, func(t *testing.T) {
			params := url.Values{"client_id": {"public"}, "redirect_uri": {"https://app.example/callback"}, "response_type": {"code"}, "scope": {"openid"}, "state": {"outer-state"}, "request": {object}, "code_challenge": {protocol.NewSHACodeChallenge(strings.Repeat("v", 43))}, "code_challenge_method": {"S256"}}
			if mode != "" {
				params.Set("response_mode", mode)
			}
			response := request(p, b, http.MethodGet, "/authorize?"+params.Encode(), nil)
			var fields url.Values
			if mode == "form_post" {
				fields = formFields(t, response)
				require.Contains(t, response.Body.String(), `action="https://app.example/callback"`)
			} else {
				require.Equal(t, 302, response.Code)
				callback, err := url.Parse(response.Header().Get("Location"))
				require.NoError(t, err)
				require.Equal(t, "app.example", callback.Host)
				fields = callback.Query()
			}
			require.Equal(t, "request_not_supported", fields.Get("error"))
			require.Equal(t, "outer-state", fields.Get("state"))
			require.Empty(t, fields.Get("code"))
			require.NotContains(t, response.Body.String(), "untrusted.example")
		})
	}
}

func TestMFACycleNeverRevivesOriginalTokens(t *testing.T) {
	p, browser, users := testProvider(t)
	code, verifier := authorizeCode(t, p, browser, nil)
	out := tokens(t, exchange(p, code, verifier, "public"))
	users.user.TwoFactorVersion++
	secret := "encrypted-key"
	now := time.Now()
	users.user.TwoFactorSecret, users.user.TwoFactorConfirmedAt = &secret, &now
	_, err := p.ResolveAccessToken(context.Background(), out.AccessToken, "https://api.example")
	require.ErrorIs(t, err, ErrInvalidGrant)
	users.user.TwoFactorVersion++
	users.user.TwoFactorSecret, users.user.TwoFactorConfirmedAt = nil, nil
	_, err = p.ResolveAccessToken(context.Background(), out.AccessToken, "https://api.example")
	require.ErrorIs(t, err, ErrInvalidGrant)
	require.Equal(t, 400, refresh(p, out.RefreshToken, "public", "").Code)
}
