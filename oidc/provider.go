package oidc

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	protocol "github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// Provider adapts the protocol SDK to Authkit services. The SDK and its types
// are implementation details; host applications use Config, Client and Service.
type Provider struct {
	protocol *op.Provider
	Service  *Service
	storage  *storage
	path     string
}

func New(c Config, store Store, users UserStore, hasher PasswordHasher) (*Provider, error) {
	if !c.Enabled {
		return nil, nil
	}
	c = c.defaults()
	if err := c.validate(); err != nil {
		return nil, err
	}
	if store == nil || users == nil || hasher == nil {
		return nil, ErrValidation
	}
	s := &storage{service: newService(c, store, users, hasher)}
	var set jose.JSONWebKeySet
	if json.Unmarshal([]byte(c.SigningKeysJSON), &set) != nil {
		return nil, ErrValidation
	}
	seen := map[string]bool{}
	for _, k := range set.Keys {
		if !k.Valid() || k.KeyID == "" || seen[k.KeyID] || (k.Algorithm != "" && k.Algorithm != string(jose.RS256)) || (k.Use != "" && k.Use != "sig") {
			return nil, ErrValidation
		}
		seen[k.KeyID] = true
		pub, ok := k.Public().Key.(*rsa.PublicKey)
		if !ok || pub.N.BitLen() < 2048 {
			return nil, ErrValidation
		}
		k.Algorithm = string(jose.RS256)
		k.Use = "sig"
		s.keys = append(s.keys, k.Public())
		if k.KeyID == c.SigningKeyID {
			if _, ok := k.Key.(*rsa.PrivateKey); !ok {
				return nil, ErrValidation
			}
			s.signing = k
		}
	}
	if s.signing.Key == nil {
		return nil, ErrValidation
	}
	if _, err := op.SignerFromKey(signingKey{key: s.signing}); err != nil {
		return nil, ErrValidation
	}
	var active op.Crypto
	var decrypters []op.Decrypter
	for id, encoded := range c.EncryptionKeys {
		value, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(value) != 32 || id == "" {
			return nil, ErrValidation
		}
		var key [32]byte
		copy(key[:], value)
		crypto := op.NewAES256GCMCrypto(key, id)
		decrypters = append(decrypters, crypto)
		if id == c.EncryptionKeyID {
			active = crypto
		}
	}
	if active == nil {
		return nil, ErrValidation
	}
	options := []op.Option{op.WithCrypto(op.NewCompositeCrypto(active, decrypters))}
	if c.AllowInsecureLoopback {
		options = append(options, op.WithAllowInsecure())
	}
	sdk, err := op.NewProvider(&op.Config{CodeMethodS256: true, GrantTypeRefreshToken: true, AuthMethodPost: true, SupportedScopes: c.Scopes, SupportedClaims: []string{"iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "amr", "azp", "at_hash", "name", "picture", "email", "email_verified"}}, s, op.StaticIssuer(c.Issuer), options...)
	if err != nil {
		return nil, fmt.Errorf("OIDC provider initialization failed: %w", err)
	}
	u, _ := url.Parse(c.Issuer)
	return &Provider{protocol: sdk, Service: s.service, storage: s, path: u.Path}, nil
}

func (p *Provider) Issuer() string { return p.Service.config.Issuer }
func (p *Provider) Path() string   { return p.path }

// ServeHTTP only exposes the supported protocol surface. Internal SDK callback,
// implicit/device grants, end_session and introspection are not mounted.
func (p *Provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r = r.WithContext(op.ContextWithIssuer(r.Context(), p.Issuer()))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	path := strings.TrimPrefix(r.URL.Path, p.path)
	if p.cors(w, r, path) {
		return
	}
	switch path {
	case "/.well-known/openid-configuration":
		if !method(w, r, http.MethodGet) {
			return
		}
		d := op.CreateDiscoveryConfig(r.Context(), p.protocol, p.storage)
		d.ResponseTypesSupported = []string{"code"}
		d.ResponseModesSupported = []string{"query", "form_post"}
		d.GrantTypesSupported = []protocol.GrantType{protocol.GrantTypeCode, protocol.GrantTypeRefreshToken}
		d.IntrospectionEndpoint = ""
		d.IntrospectionEndpointAuthMethodsSupported = nil
		d.IntrospectionEndpointAuthSigningAlgValuesSupported = nil
		d.EndSessionEndpoint = ""
		d.DeviceAuthorizationEndpoint = ""
		d.CheckSessionIframe = ""
		d.RequestObjectSigningAlgValuesSupported = nil
		op.Discover(w, d)
	case "/keys":
		if method(w, r, http.MethodGet) {
			op.Keys(w, r, p.storage)
		}
	case "/authorize":
		if !method(w, r, http.MethodGet, http.MethodPost) {
			return
		}
		if !parseForm(w, r) {
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), requestURIKey{}, r.Form.Has("request_uri")))
		p.authorize(w, r)
	case "/interaction":
		if !method(w, r, http.MethodGet, http.MethodPost) {
			return
		}
		if !parseForm(w, r) {
			return
		}
		p.interact(w, r)
	case "/oauth/token":
		if scheme, _, ok := strings.Cut(r.Header.Get("Authorization"), " "); ok && strings.EqualFold(scheme, "Basic") {
			w = basicChallengeWriter{w}
		}
		if !p.tokenForm(w, r) {
			return
		}
		if r.PostForm.Get("grant_type") == "authorization_code" && r.PostForm.Has("code_verifier") && !validVerifier(r.PostForm.Get("code_verifier")) {
			op.RequestError(w, r, protocol.ErrInvalidGrant(), nil)
			return
		}
		op.Exchange(w, r, p.protocol)
	case "/revoke":
		if scheme, _, ok := strings.Cut(r.Header.Get("Authorization"), " "); ok && strings.EqualFold(scheme, "Basic") {
			w = basicChallengeWriter{w}
		}
		if !p.tokenForm(w, r) {
			return
		}
		op.Revoke(w, r, p.protocol)
	case "/userinfo":
		if !method(w, r, http.MethodGet, http.MethodPost) {
			return
		}
		if !parseForm(w, r) {
			return
		}
		p.userinfo(w, r)
	default:
		http.NotFound(w, r)
	}
}

type basicChallengeWriter struct{ http.ResponseWriter }

func (w basicChallengeWriter) WriteHeader(status int) {
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Basic realm="oidc"`)
	}
	w.ResponseWriter.WriteHeader(status)
}

func method(w http.ResponseWriter, r *http.Request, allowed ...string) bool {
	if slices.Contains(allowed, r.Method) {
		return true
	}
	w.Header().Set("Allow", strings.Join(allowed, ", "))
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	return false
}
func parseForm(w http.ResponseWriter, r *http.Request) bool {
	if err := r.ParseForm(); err != nil {
		op.RequestError(w, r, protocol.ErrInvalidRequest(), nil)
		return false
	}
	for _, v := range r.Form {
		if len(v) != 1 {
			op.RequestError(w, r, protocol.ErrInvalidRequest(), nil)
			return false
		}
	}
	return true
}
func (p *Provider) tokenForm(w http.ResponseWriter, r *http.Request) bool {
	if !method(w, r, http.MethodPost) {
		return false
	}
	kind, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || kind != "application/x-www-form-urlencoded" || r.URL.RawQuery != "" {
		op.RequestError(w, r, protocol.ErrInvalidRequest(), nil)
		return false
	}
	if !parseForm(w, r) {
		return false
	}
	if r.PostForm.Has("client_assertion") || r.PostForm.Has("client_assertion_type") {
		op.RequestError(w, r, protocol.ErrInvalidClient(), nil)
		return false
	}
	id := r.PostForm.Get("client_id")
	auth := r.Header.Get("Authorization")
	if auth != "" {
		var ok bool
		id, _, ok = r.BasicAuth()
		if !ok || r.PostForm.Has("client_secret") {
			op.RequestError(w, r, protocol.ErrInvalidRequest(), nil)
			return false
		}
		var err error
		id, err = url.QueryUnescape(id)
		if err != nil {
			op.RequestError(w, r, protocol.ErrInvalidClient(), nil)
			return false
		}
		if supplied := r.PostForm.Get("client_id"); supplied != "" && supplied != id {
			op.RequestError(w, r, protocol.ErrInvalidClient(), nil)
			return false
		}
	}
	c, err := p.Service.client(r.Context(), id)
	if err != nil {
		op.RequestError(w, r, protocolError(err), nil)
		return false
	}
	valid := c.AuthMethod == "none" && auth == "" && !r.PostForm.Has("client_secret") ||
		c.AuthMethod == "client_secret_basic" && auth != "" ||
		c.AuthMethod == "client_secret_post" && auth == "" && r.PostForm.Has("client_secret")
	if !valid {
		op.RequestError(w, r, protocol.ErrInvalidClient(), nil)
		return false
	}
	return true
}

func validVerifier(value string) bool {
	if len(value) < 43 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || strings.ContainsRune("-._~", r)) {
			return false
		}
	}
	return true
}

// Browser clients use explicitly configured origins. Credentials are never
// enabled: token/UserInfo endpoints authenticate through protocol credentials.
func (p *Provider) cors(w http.ResponseWriter, r *http.Request, path string) bool {
	public := path == "/.well-known/openid-configuration" || path == "/keys"
	stateless := path == "/oauth/token" || path == "/revoke" || path == "/userinfo"
	if !public && !stateless {
		return false
	}
	origin := r.Header.Get("Origin")
	if public {
		w.Header().Set("Access-Control-Allow-Origin", "*")
	} else if origin != "" && slices.Contains(p.Service.config.AllowedOrigins, origin) {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Add("Vary", "Origin")
	}
	if r.Method != http.MethodOptions {
		return false
	}
	if !public && (origin == "" || !slices.Contains(p.Service.config.AllowedOrigins, origin)) {
		http.Error(w, "Origin not allowed", http.StatusForbidden)
		return true
	}
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	w.WriteHeader(http.StatusNoContent)
	return true
}

type requestURIKey struct{}

func (p *Provider) validateAuthRequest(ctx context.Context, req *protocol.AuthRequest, client op.Client) (string, error) {
	if !registeredRedirect(client.RedirectURIs(), req.RedirectURI, client.ApplicationType() == op.ApplicationTypeNative) {
		return "", protocol.ErrInvalidRequestRedirectURI()
	}
	if supplied, _ := ctx.Value(requestURIKey{}).(bool); supplied {
		return "", &protocol.Error{ErrorType: "request_uri_not_supported"}
	}
	if req.ResponseType != protocol.ResponseTypeCode {
		return "", &protocol.Error{ErrorType: "unsupported_response_type"}
	}
	c := client.(*clientSnapshot).row
	if req.CodeChallenge == "" && req.CodeChallengeMethod == "" && !c.requiresPKCE() {
		// A confidential client may explicitly opt into the Core flow without PKCE.
	} else if req.CodeChallengeMethod != protocol.CodeChallengeMethodS256 || len(req.CodeChallenge) != 43 {
		return "", protocol.ErrInvalidRequest()
	}
	decoded, err := base64.RawURLEncoding.DecodeString(req.CodeChallenge)
	if req.CodeChallenge != "" && (err != nil || len(decoded) != 32) {
		return "", protocol.ErrInvalidRequest()
	}
	if !slices.Contains(req.Scopes, "openid") || !subset(req.Scopes, c.Scopes) {
		return "", protocol.ErrInvalidScope()
	}
	if slices.Contains(req.Scopes, "offline_access") && !c.AllowRefresh {
		return "", protocol.ErrInvalidScope()
	}
	if req.ResponseMode != "" && req.ResponseMode != protocol.ResponseModeQuery && req.ResponseMode != protocol.ResponseModeFormPost {
		return "", protocol.ErrInvalidRequest()
	}
	if req.ResponseMode == protocol.ResponseModeFormPost {
		u, err := url.Parse(req.RedirectURI)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return "", protocol.ErrInvalidRequest()
		}
	}
	for _, v := range req.Prompt {
		if !slices.Contains([]string{"none", "login", "consent", "select_account"}, v) {
			return "", protocol.ErrInvalidRequest()
		}
	}
	return op.ValidateAuthRequestClient(ctx, req, client, p.protocol.IDTokenHintVerifier(ctx))
}

func registeredRedirect(allowed []string, raw string, native bool) bool {
	if slices.Contains(allowed, raw) {
		return true
	}
	u, err := url.Parse(raw)
	if err != nil || !native || u.Scheme != "http" || !loopback(u.Hostname()) || u.User != nil || u.Fragment != "" {
		return false
	}
	for _, v := range allowed {
		a, err := url.Parse(v)
		if err == nil && a.Scheme == u.Scheme && a.Hostname() == u.Hostname() && a.EscapedPath() == u.EscapedPath() && a.RawQuery == u.RawQuery {
			return true
		}
	}
	return false
}

func (p *Provider) ResolveAccessToken(ctx context.Context, value, audience string, requiredScopes ...string) (*Identity, error) {
	if audience == "" {
		return nil, ErrValidation
	}
	plain, err := p.protocol.Crypto().Decrypt(value)
	if err != nil {
		return nil, ErrInvalidGrant
	}
	parts := strings.Split(plain, ":")
	if len(parts) != 2 {
		return nil, ErrInvalidGrant
	}
	t, g, _, err := p.Service.access(ctx, parts[0], parts[1])
	if err != nil {
		return nil, err
	}
	if !slices.Contains(g.Audience, audience) {
		return nil, ErrInvalidGrant
	}
	if !subset(requiredScopes, t.Scopes) {
		return nil, ErrForbidden
	}
	return &Identity{UserID: g.UserID, ClientID: g.ClientID, ConnectionID: g.ID, Scopes: slices.Clone(t.Scopes), Audience: slices.Clone(g.Audience)}, nil
}

func parseSubject(value string) (uuid.UUID, error) {
	id, err := uuid.Parse(value)
	if err != nil || id == uuid.Nil {
		return uuid.Nil, protocol.ErrInvalidGrant()
	}
	return id, nil
}

var consentPage = template.Must(template.New("consent").Parse(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Authorize application</title><main><h1>Authorize {{.Name}}</h1><p>Continue as {{.Account}}?</p><p>Requested scopes: {{.Scopes}}</p><form method="post" action="{{.Action}}"><input type="hidden" name="id" value="{{.ID}}"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><button name="decision" value="approve">Allow access</button><button name="decision" value="deny">Deny</button></form></main></html>`))

func (p *Provider) interact(w http.ResponseWriter, r *http.Request) {
	b := browserFrom(r.Context())
	result, err := p.Service.interaction(r.Context(), r.Form.Get("id"), b, r.Method == http.MethodPost, r.Form.Get("decision"), r.Form.Get("csrf_token"))
	if err != nil {
		if result == nil {
			op.RequestError(w, r, protocolError(err), nil)
		} else {
			p.authorizationError(w, r, result.request, err)
		}
		return
	}
	switch result.next {
	case "login":
		login, _ := url.Parse(p.Service.config.LoginURL)
		query := login.Query()
		query.Set("return_to", p.Issuer()+"/interaction?id="+url.QueryEscape(result.request.GetID()))
		query.Set("prompt", "login")
		login.RawQuery = query.Encode()
		http.Redirect(w, r, login.String(), http.StatusFound)
	case "consent":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		w.Header().Set("X-Frame-Options", "DENY")
		_ = consentPage.Execute(w, struct{ Name, Account, Scopes, ID, CSRF, Action string }{result.client.Name, result.user.Email, strings.Join(result.request.row.Scopes, " "), result.request.GetID(), result.csrf, p.Issuer() + "/interaction"})
	case "authorized":
		p.authorizationResponse(w, r, result.request)
	}
}

// IsAuthenticationError distinguishes invalid credentials from an unavailable
// security-state backend without exposing internal errors to an API caller.
func IsAuthenticationError(err error) bool {
	return errors.Is(err, ErrInvalidGrant) || errors.Is(err, ErrInvalidClient)
}
