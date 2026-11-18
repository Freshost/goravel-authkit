package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"time"

	"github.com/go-jose/go-jose/v4"
	protocol "github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/freshost/goravel-authkit/models"
)

type browserKey struct{}

func WithBrowser(ctx context.Context, b Browser) context.Context {
	return context.WithValue(ctx, browserKey{}, b)
}
func browserFrom(ctx context.Context) Browser { b, _ := ctx.Value(browserKey{}).(Browser); return b }

type storage struct {
	service *Service
	keys    []jose.JSONWebKey
	signing jose.JSONWebKey
}

var _ op.Storage = (*storage)(nil)
var _ op.CanSetUserinfoFromRequest = (*storage)(nil)

type requestSnapshot struct {
	row      *authorization
	original protocol.AuthRequest
}

func snapshot(a *authorization) (*requestSnapshot, error) {
	var req protocol.AuthRequest
	if err := json.Unmarshal([]byte(a.Payload), &req); err != nil {
		return nil, err
	}
	return &requestSnapshot{row: a, original: req}, nil
}
func (a *requestSnapshot) GetID() string          { return a.row.ID }
func (a *requestSnapshot) GetACR() string         { return "" }
func (a *requestSnapshot) GetAMR() []string       { return slices.Clone(a.row.AMR) }
func (a *requestSnapshot) GetAudience() []string  { return []string{a.row.ClientID} }
func (a *requestSnapshot) GetAuthTime() time.Time { return a.row.AuthTime }
func (a *requestSnapshot) GetClientID() string    { return a.row.ClientID }
func (a *requestSnapshot) GetCodeChallenge() *protocol.CodeChallenge {
	return &protocol.CodeChallenge{Challenge: a.original.CodeChallenge, Method: a.original.CodeChallengeMethod}
}
func (a *requestSnapshot) GetNonce() string                       { return a.original.Nonce }
func (a *requestSnapshot) GetRedirectURI() string                 { return a.original.RedirectURI }
func (a *requestSnapshot) GetResponseType() protocol.ResponseType { return a.original.ResponseType }
func (a *requestSnapshot) GetResponseMode() protocol.ResponseMode { return a.original.ResponseMode }
func (a *requestSnapshot) GetScopes() []string                    { return slices.Clone(a.row.Scopes) }
func (a *requestSnapshot) GetState() string                       { return a.original.State }
func (a *requestSnapshot) GetSubject() string                     { return a.row.UserID.String() }
func (a *requestSnapshot) Done() bool                             { return a.row.Approved }

type refreshSnapshot struct {
	grant  *Connection
	scopes []string
}

func (a *refreshSnapshot) GetAMR() []string            { return slices.Clone(a.grant.AMR) }
func (a *refreshSnapshot) GetAudience() []string       { return []string{a.grant.ClientID} }
func (a *refreshSnapshot) GetAuthTime() time.Time      { return a.grant.AuthTime }
func (a *refreshSnapshot) GetClientID() string         { return a.grant.ClientID }
func (a *refreshSnapshot) GetScopes() []string         { return slices.Clone(a.scopes) }
func (a *refreshSnapshot) GetSubject() string          { return a.grant.UserID.String() }
func (a *refreshSnapshot) SetCurrentScopes(v []string) { a.scopes = slices.Clone(v) }

type clientSnapshot struct {
	row    *Client
	config Config
}

func (c *clientSnapshot) GetID() string                    { return c.row.ID }
func (c *clientSnapshot) RedirectURIs() []string           { return slices.Clone(c.row.RedirectURIs) }
func (c *clientSnapshot) PostLogoutRedirectURIs() []string { return nil }
func (c *clientSnapshot) ApplicationType() op.ApplicationType {
	if c.row.ApplicationType == "native" {
		return op.ApplicationTypeNative
	}
	if c.row.AuthMethod == "none" {
		return op.ApplicationTypeUserAgent
	}
	return op.ApplicationTypeWeb
}
func (c *clientSnapshot) AuthMethod() protocol.AuthMethod {
	return protocol.AuthMethod(c.row.AuthMethod)
}
func (c *clientSnapshot) ResponseTypes() []protocol.ResponseType {
	return []protocol.ResponseType{protocol.ResponseTypeCode}
}
func (c *clientSnapshot) GrantTypes() []protocol.GrantType {
	v := []protocol.GrantType{protocol.GrantTypeCode}
	if c.row.AllowRefresh {
		v = append(v, protocol.GrantTypeRefreshToken)
	}
	return v
}
func (c *clientSnapshot) LoginURL(id string) string {
	return c.config.Issuer + "/interaction?id=" + url.QueryEscape(id)
}
func (c *clientSnapshot) AccessTokenType() op.AccessTokenType { return op.AccessTokenTypeBearer }
func (c *clientSnapshot) IDTokenLifetime() time.Duration      { return c.config.IDTokenLifetime }
func (c *clientSnapshot) DevMode() bool                       { return false }
func (c *clientSnapshot) RestrictAdditionalIdTokenScopes() func([]string) []string {
	return func(v []string) []string { return slices.Clone(v) }
}
func (c *clientSnapshot) RestrictAdditionalAccessTokenScopes() func([]string) []string {
	return func(v []string) []string { return slices.Clone(v) }
}
func (c *clientSnapshot) IsScopeAllowed(v string) bool         { return slices.Contains(c.row.Scopes, v) }
func (c *clientSnapshot) IDTokenUserinfoClaimsAssertion() bool { return false }
func (c *clientSnapshot) ClockSkew() time.Duration             { return 0 }

func (s *storage) GetClientByClientID(ctx context.Context, id string) (op.Client, error) {
	c, err := s.service.client(ctx, id)
	if err != nil {
		return nil, protocolError(err)
	}
	return &clientSnapshot{row: c, config: s.service.config}, nil
}
func (s *storage) AuthorizeClientIDSecret(ctx context.Context, id, secret string) error {
	c, err := s.service.client(ctx, id)
	if err != nil {
		return protocolError(err)
	}
	if c.AuthMethod != "client_secret_basic" || !s.service.hasher.Check(secret, c.SecretHash) {
		return protocol.ErrInvalidClient()
	}
	return nil
}

func (s *storage) CreateAuthRequest(ctx context.Context, req *protocol.AuthRequest, hintSubject string) (op.AuthRequest, error) {
	b := browserFrom(ctx)
	if b.Binding == "" {
		return nil, protocol.ErrInvalidRequest()
	}
	if b.Impersonating {
		return nil, protocol.ErrAccessDenied()
	}
	c, err := s.service.client(ctx, req.ClientID)
	if err != nil {
		return nil, protocolError(err)
	}
	validatedVersion, ok := ctx.Value(validatedClientKey{}).(int64)
	if !ok || validatedVersion != c.Version {
		return nil, protocol.ErrInvalidGrant()
	}
	id, err := randomValue()
	if err != nil {
		return nil, protocolError(err)
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, protocolError(err)
	}
	now := s.service.now()
	a := &authorization{ID: id, ClientID: c.ID, ClientVersion: c.Version, Payload: string(payload), BindingHash: digest(b.Binding), InitialEvent: b.AuthEvent, HintSubject: hintSubject, Scopes: slices.Clone([]string(req.Scopes)), Audience: slices.Clone(c.Audience), CreatedAt: now, ExpiresAt: now.Add(s.service.config.RequestLifetime)}
	if err = s.service.store.SaveRequest(ctx, a); err != nil {
		return nil, protocolError(err)
	}
	return snapshot(a)
}

func (s *storage) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	a, err := s.service.store.Request(ctx, id, false)
	if err != nil {
		return nil, protocolError(err)
	}
	if a == nil || !s.service.now().Before(a.ExpiresAt) {
		return nil, protocol.ErrInvalidGrant()
	}
	return snapshot(a)
}
func (s *storage) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	a, err := s.service.store.RequestByCode(ctx, digest(code))
	if err != nil {
		return nil, protocolError(err)
	}
	if a == nil {
		return nil, protocol.ErrInvalidGrant()
	}
	return snapshot(a)
}
func (s *storage) SaveAuthCode(ctx context.Context, id, code string) error {
	return protocolError(s.service.store.Transaction(ctx, func(tx Store) error {
		a, err := tx.Request(ctx, id, true)
		if err != nil {
			return err
		}
		b := browserFrom(ctx)
		if a == nil || !a.Approved || a.CodeHash != nil || a.ConsumedAt != nil || a.BindingHash != digest(b.Binding) || !s.service.now().Before(a.ExpiresAt) {
			return ErrInvalidGrant
		}
		if _, err = s.service.liveUser(ctx, a.UserID, a.CredentialStamp, a.TwoFactorStamp); err != nil {
			return err
		}
		hash := digest(code)
		expiry := s.service.now().Add(s.service.config.CodeLifetime)
		a.CodeHash = &hash
		a.CodeExpiresAt = &expiry
		return tx.SaveRequest(ctx, a)
	}))
}
func (s *storage) DeleteAuthRequest(context.Context, string) error { return nil } // retained as a replay tombstone until grant expiry

func (s *storage) CreateAccessToken(ctx context.Context, req op.TokenRequest) (string, time.Time, error) {
	a, ok := req.(*requestSnapshot)
	if !ok {
		return "", time.Time{}, protocol.ErrUnsupportedGrantType()
	}
	id, _, exp, err := s.service.issue(ctx, a.GetID(), "", req.GetScopes(), false)
	return id, exp, protocolError(err)
}
func (s *storage) CreateAccessAndRefreshTokens(ctx context.Context, req op.TokenRequest, current string) (string, string, time.Time, error) {
	id := ""
	switch a := req.(type) {
	case *requestSnapshot:
		if current != "" {
			return "", "", time.Time{}, protocol.ErrInvalidGrant()
		}
		id = a.GetID()
	case *refreshSnapshot:
		if current == "" {
			return "", "", time.Time{}, protocol.ErrInvalidGrant()
		}
	default:
		return "", "", time.Time{}, protocol.ErrUnsupportedGrantType()
	}
	access, refresh, exp, err := s.service.issue(ctx, id, current, req.GetScopes(), true)
	return access, refresh, exp, protocolError(err)
}
func (s *storage) TokenRequestByRefreshToken(ctx context.Context, value string) (op.RefreshTokenRequest, error) {
	t, err := s.service.store.Refresh(ctx, digest(value), false)
	if err != nil {
		return nil, protocolError(err)
	}
	if t == nil {
		return nil, protocol.ErrInvalidGrant()
	}
	g, err := s.service.store.Grant(ctx, t.GrantID, false)
	if err != nil {
		return nil, protocolError(err)
	}
	if g == nil {
		return nil, protocol.ErrInvalidGrant()
	}
	return &refreshSnapshot{grant: g, scopes: slices.Clone(t.Scopes)}, nil
}
func (s *storage) GetRefreshTokenInfo(ctx context.Context, clientID, value string) (string, string, error) {
	t, err := s.service.store.Refresh(ctx, digest(value), false)
	if err != nil {
		return "", "", protocolError(err)
	}
	if t == nil {
		return "", "", op.ErrInvalidRefreshToken
	}
	g, err := s.service.store.Grant(ctx, t.GrantID, false)
	if err != nil {
		return "", "", protocolError(err)
	}
	if g == nil || g.ClientID != clientID {
		return "", "", op.ErrInvalidRefreshToken
	}
	return g.UserID.String(), t.ID, nil
}
func (s *storage) RevokeToken(ctx context.Context, id, subject, clientID string) *protocol.Error {
	err := protocolError(s.service.revokeToken(ctx, id, subject, clientID))
	if err == nil {
		return nil
	}
	return err.(*protocol.Error)
}
func (s *storage) TerminateSession(context.Context, string, string) error {
	return protocol.ErrInvalidRequest()
} // end_session is not advertised or mounted

func (s *storage) SetUserinfoFromScopes(context.Context, *protocol.UserInfo, string, string, []string) error {
	return nil
}
func (s *storage) SetUserinfoFromRequest(ctx context.Context, info *protocol.UserInfo, req op.IDTokenRequest, scopes []string) error {
	var id string
	switch a := req.(type) {
	case *requestSnapshot:
		id = a.row.UserID.String()
	case *refreshSnapshot:
		id = a.grant.UserID.String()
	default:
		return protocol.ErrInvalidGrant()
	}
	uID, err := parseSubject(id)
	if err != nil {
		return err
	}
	u, err := s.service.users.FindByID(ctx, uID)
	if err != nil {
		return protocolError(err)
	}
	if u == nil || u.IsDisabled() {
		return protocol.ErrInvalidGrant()
	}
	setUserinfo(info, u, scopes)
	return nil
}
func (s *storage) SetUserinfoFromToken(ctx context.Context, info *protocol.UserInfo, id, subject, origin string) error {
	t, _, u, err := s.service.access(ctx, id, subject)
	if err != nil {
		return protocolError(err)
	}
	setUserinfo(info, u, t.Scopes)
	return nil
}
func setUserinfo(info *protocol.UserInfo, u *models.User, scopes []string) {
	info.Subject = u.ID.String()
	if slices.Contains(scopes, "profile") {
		if u.Name != nil {
			info.Name = *u.Name
		}
		if u.Image != nil {
			info.Picture = *u.Image
		}
	}
	if slices.Contains(scopes, "email") {
		info.Email = u.Email
		info.EmailVerified = protocol.Bool(u.EmailVerified != nil)
	}
}
func (s *storage) SetIntrospectionFromToken(context.Context, *protocol.IntrospectionResponse, string, string, string) error {
	return protocol.ErrAccessDenied()
}
func (s *storage) GetPrivateClaimsFromScopes(context.Context, string, string, []string) (map[string]any, error) {
	return nil, nil
}
func (s *storage) GetKeyByIDAndClientID(context.Context, string, string) (*jose.JSONWebKey, error) {
	return nil, protocol.ErrInvalidClient()
}
func (s *storage) ValidateJWTProfileScopes(context.Context, string, []string) ([]string, error) {
	return nil, protocol.ErrUnsupportedGrantType()
}
func (s *storage) Health(context.Context) error { return nil }

type signingKey struct{ key jose.JSONWebKey }

func (k signingKey) ID() string                                  { return k.key.KeyID }
func (k signingKey) Key() any                                    { return k.key.Key }
func (k signingKey) SignatureAlgorithm() jose.SignatureAlgorithm { return jose.RS256 }
func (k signingKey) Algorithm() jose.SignatureAlgorithm          { return jose.RS256 }
func (k signingKey) Use() string                                 { return "sig" }
func (s *storage) SigningKey(context.Context) (op.SigningKey, error) {
	return signingKey{key: s.signing}, nil
}
func (s *storage) SignatureAlgorithms(context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{jose.RS256}, nil
}
func (s *storage) KeySet(context.Context) ([]op.Key, error) {
	result := make([]op.Key, 0, len(s.keys))
	for _, k := range s.keys {
		result = append(result, signingKey{key: k.Public()})
	}
	return result, nil
}

func protocolError(err error) error {
	if err == nil {
		return nil
	}
	var existing *protocol.Error
	if errors.As(err, &existing) {
		safe := *existing
		safe.Parent = nil
		return &safe
	}
	switch {
	case errors.Is(err, ErrInvalidClient):
		return protocol.ErrInvalidClient()
	case errors.Is(err, ErrInvalidGrant):
		return protocol.ErrInvalidGrant()
	case errors.Is(err, ErrForbidden):
		return protocol.ErrAccessDenied()
	case errors.Is(err, ErrLoginRequired):
		return protocol.ErrLoginRequired()
	case errors.Is(err, ErrValidation):
		return protocol.ErrInvalidRequest()
	case errors.Is(err, ErrConsentRequired):
		return &protocol.Error{ErrorType: "consent_required"}
	default:
		return protocol.ErrServerError()
	}
}
