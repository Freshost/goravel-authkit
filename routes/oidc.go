package routes

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	contractshttp "github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/contracts/route"
	"github.com/goravel/framework/facades"
	sessionmiddleware "github.com/goravel/framework/session/middleware"

	authcontracts "github.com/freshost/goravel-authkit/contracts"
	"github.com/freshost/goravel-authkit/helpers"
	"github.com/freshost/goravel-authkit/http/middleware"
	"github.com/freshost/goravel-authkit/oidc"
	"github.com/freshost/goravel-authkit/repositories"
	"github.com/freshost/goravel-authkit/services"
)

// OIDCProviderConfig reads the independent provider configuration. No outbound
// OIDC client is initialized by these settings.
func OIDCProviderConfig() oidc.Config {
	cfg := facades.Config()
	if cfg == nil || !cfg.GetBool("authkit.oidc.provider.enabled", false) {
		return oidc.Config{}
	}
	base := "authkit.oidc.provider."
	c := oidc.Config{Enabled: true, Issuer: cfg.GetString(base + "issuer"), Guard: cfg.GetString(base + "guard"), LoginURL: cfg.GetString(base + "login_url"), SigningKeyID: cfg.GetString(base + "signing_key_id"), SigningKeysJSON: cfg.GetString(base + "signing_keys"), EncryptionKeyID: cfg.GetString(base + "encryption_key_id"), EncryptionKeys: map[string]string{}, Scopes: toStringSlice(cfg.Get(base + "scopes")), AllowInsecureLoopback: cfg.GetBool(base+"allow_insecure_loopback", false)}
	c.AllowedOrigins = toStringSlice(cfg.Get(base + "cors.allowed_origins"))
	c.ConsentTemplate = cfg.GetString(base + "consent_template")
	if values, ok := cfg.Get(base + "encryption_keys").(map[string]any); ok {
		for k, v := range values {
			if value, ok := v.(string); ok {
				c.EncryptionKeys[k] = value
			}
		}
	}
	if values, ok := cfg.Get(base + "encryption_keys").(map[string]string); ok {
		c.EncryptionKeys = values
	}
	for key, dest := range map[string]*time.Duration{"access_token_lifetime_seconds": &c.AccessTokenLifetime, "id_token_lifetime_seconds": &c.IDTokenLifetime, "code_lifetime_seconds": &c.CodeLifetime, "request_lifetime_seconds": &c.RequestLifetime, "refresh_idle_lifetime_seconds": &c.RefreshIdleLifetime, "refresh_absolute_lifetime_seconds": &c.RefreshAbsoluteLifetime} {
		if cfg.Get(base+key) != nil {
			value := cfg.GetInt(base + key)
			if value <= 0 {
				*dest = -1
			} else {
				*dest = time.Duration(value) * time.Second
			}
		}
	}
	return c
}

// NewOIDCProvider resolves the configured provider for administration or custom
// host integrations. Disabled configuration returns (nil, nil).
func NewOIDCProvider() (*oidc.Provider, error) {
	c := OIDCProviderConfig()
	if !c.Enabled {
		return nil, nil
	}
	for _, o := range GuardOptions() {
		if o.Guard == c.Guard {
			if o.EnableAuditLog {
				audit := services.NewAudit(repositories.NewAuditWithTable(o.AuditTable))
				c.Audit = func(ctx context.Context, event oidc.Event) {
					var user *uuid.UUID
					if event.UserID != uuid.Nil {
						id := event.UserID
						user = &id
					}
					_ = audit.Log(ctx, services.AuditEntry{ActorID: user, Action: event.Action, ResourceType: "oidc_connection", ResourceID: &event.ConnectionID, Metadata: map[string]any{"client_id": event.ClientID}})
				}
			}
			return oidc.New(c, oidc.NewStore(c.Issuer), repositories.NewUsersWithTable(o.UsersTable), services.NewFacadeHasher())
		}
	}
	return nil, fmt.Errorf("OIDC provider guard is not configured")
}

// RegisterOIDC mounts only the configured OIDC provider. RegisterAll already
// calls it; custom hosts must choose one registration path to avoid duplicates.
func RegisterOIDC(router route.Router) {
	p, err := NewOIDCProvider()
	if err != nil {
		panic(err)
	}
	if p == nil {
		return
	}
	opts := optionsByGuard(OIDCProviderConfig().Guard)
	rateStore := opts.RateLimitStore
	if rateStore == nil {
		rateStore = authcontracts.RegisteredRateLimitStore()
	}
	if rateStore == nil {
		rateStore = middleware.DefaultRateLimitStore()
	}
	limiter := middleware.NewAttemptLimiter(rateStore, "authkit:"+opts.Guard+":oidc", opts.RateLimitWindow)
	ipLimit := facades.Config().GetInt("authkit.oidc.provider.rate_limit.ip_attempts", opts.RateLimitIPAttempts)
	if ipLimit <= 0 {
		panic("OIDC provider rate limit must be positive")
	}
	serve := func(ctx contractshttp.Context) contractshttp.Response {
		if ctx.Request().Origin().Method != "OPTIONS" {
			path := ctx.Request().Origin().URL.Path
			if strings.HasSuffix(path, "/authorize") || strings.HasSuffix(path, "/interaction") || strings.HasSuffix(path, "/oauth/token") || strings.HasSuffix(path, "/revoke") {
				result, err := limiter.Hit(ctx.Context(), "ip", ctx.Request().Ip(), ipLimit)
				if err != nil {
					return ctx.Response().Json(503, contractshttp.Json{"error": "temporarily_unavailable"})
				}
				if !result.Allowed {
					ctx.Response().Header("Retry-After", strconv.Itoa(int(result.RetryAfter.Seconds())+1))
					return ctx.Response().Json(429, contractshttp.Json{"error": "temporarily_unavailable"})
				}
			}
		}
		p.ServeHTTP(ctx.Response().Writer(), ctx.Request().Origin().WithContext(ctx.Context()))
		return nil
	}
	for _, path := range []string{"/.well-known/openid-configuration", "/keys"} {
		router.Get(p.Path()+path, serve)
		router.Options(p.Path()+path, serve)
	}
	for _, path := range []string{"/oauth/token", "/revoke"} {
		router.Post(p.Path()+path, serve)
		router.Options(p.Path()+path, serve)
	}
	router.Get(p.Path()+"/userinfo", serve)
	router.Post(p.Path()+"/userinfo", serve)
	router.Options(p.Path()+"/userinfo", serve)
	// Protocol browser routes deliberately do not use Authenticated: the
	// provider must return login_required or redirect through the existing UI.
	chain := []contractshttp.Middleware{sessionmiddleware.StartSession()}
	users := repositories.NewUsersWithTable(opts.UsersTable)
	var sessions *services.Sessions
	if opts.EnableSessions {
		sessions = services.NewSessions(repositories.NewSessionsWithTable(opts.SessionsTable, opts.RememberTokensTable), opts.SessionActiveWindow)
	}
	if opts.EnableRememberMe {
		remember := services.NewRemember(repositories.NewRememberWithTable(opts.RememberTokensTable), opts.RememberLifetime)
		chain = append(chain, middleware.RememberLogin(opts.Guard, opts.RememberCookieName, users, remember, nil, sessions))
	}
	chain = append(chain, &oidcBrowserMiddleware{guard: opts.Guard, users: users, sessions: sessions})
	router.Middleware(chain...).Group(func(r route.Router) {
		r.Get(p.Path()+"/authorize", serve)
		r.Post(p.Path()+"/authorize", serve)
		r.Get(p.Path()+"/interaction", serve)
		r.Middleware(middleware.VerifyRequestOrigin(opts.TrustedOrigins)).Group(func(post route.Router) {
			post.Post(p.Path()+"/interaction", serve)
		})
	})
	management := append(Protect(opts.Guard), middleware.RejectWhileImpersonating(opts.Guard), &oidcBrowserMiddleware{guard: opts.Guard, users: users, sessions: sessions, required: true})
	if !opts.EnableCSRF {
		management = append(management, middleware.VerifyRequestOrigin(opts.TrustedOrigins))
	}
	router.Prefix(opts.Prefix + "/auth/oidc/connections").Middleware(management...).Group(func(r route.Router) {
		r.Get("", func(ctx contractshttp.Context) contractshttp.Response {
			items, err := p.Service.Connections(ctx.Context(), helpers.AuthUserID(ctx))
			if err != nil {
				return ctx.Response().Json(503, contractshttp.Json{"error": "temporarily_unavailable"})
			}
			return ctx.Response().Json(200, items)
		})
		r.Delete("/{id}", func(ctx contractshttp.Context) contractshttp.Response {
			if err := p.Service.RevokeConnection(ctx.Context(), helpers.AuthUserID(ctx), ctx.Request().Route("id")); err != nil {
				return ctx.Response().Json(400, contractshttp.Json{"error": "invalid_connection"})
			}
			return ctx.Response().Json(200, contractshttp.Json{"revoked": true})
		})
		r.Delete("", func(ctx contractshttp.Context) contractshttp.Response {
			if err := p.Service.RevokeAll(ctx.Context(), helpers.AuthUserID(ctx)); err != nil {
				return ctx.Response().Json(503, contractshttp.Json{"error": "temporarily_unavailable"})
			}
			return ctx.Response().Json(200, contractshttp.Json{"revoked": true})
		})
	})
}

type oidcBrowserMiddleware struct {
	guard    string
	users    repositories.UsersRepository
	sessions *services.Sessions
	required bool
}

func (m *oidcBrowserMiddleware) Signature() string {
	return fmt.Sprintf("authkit.oidc.browser.%s.%t", m.guard, m.required)
}
func (m *oidcBrowserMiddleware) Handle(ctx contractshttp.Context) {
	sess := ctx.Request().Session()
	if sess == nil {
		_ = ctx.Response().Json(503, contractshttp.Json{"error": "temporarily_unavailable"}).Abort()
		return
	}
	key := "authkit_oidc_" + m.guard + "_browser"
	binding, _ := sess.Get(key).(string)
	if binding == "" {
		binding = helpers.NewSessionToken()
		if binding == "" {
			_ = ctx.Response().Json(503, contractshttp.Json{"error": "temporarily_unavailable"}).Abort()
			return
		}
		sess.Put(key, binding)
	}
	b := oidc.Browser{Binding: binding}
	for _, o := range GuardOptions() {
		if value := sess.Get(helpers.ImpersonatorKey(o.Guard)); value != nil && value != "" {
			b.Impersonating = true
		}
	}
	id := helpers.GuardUserID(ctx, m.guard)
	if id != uuid.Nil {
		u, err := m.users.FindByID(ctx.Context(), id)
		if err != nil {
			_ = ctx.Response().Json(503, contractshttp.Json{"error": "temporarily_unavailable"}).Abort()
			return
		}
		stamp, _ := sess.Get(helpers.PasswordChangedAtKey(m.guard)).(string)
		pending, _ := sess.Get(helpers.TwoFactorUserIDKey(m.guard)).(string)
		if u != nil && !u.IsDisabled() && stamp == middleware.FormatPasswordTimestamp(u.PasswordChangedAt) && pending == "" {
			alive := true
			if m.sessions != nil {
				alive, err = m.sessions.Touch(ctx.Context(), helpers.SessionTrackingToken(ctx, m.guard))
				if err != nil {
					_ = ctx.Response().Json(503, contractshttp.Json{"error": "temporarily_unavailable"}).Abort()
					return
				}
			}
			if alive {
				auth := helpers.SessionAuthentication(ctx, m.guard)
				b.UserID = id
				b.CredentialStamp = u.PasswordChangedAt
				b.AuthTime = auth.At
				b.AuthEvent = auth.Event
				b.AMR = auth.Methods
				b.TwoFactorStamp = auth.TwoFactorStamp
			}
		}
	}
	if m.required && (b.UserID == uuid.Nil || b.Impersonating) {
		_ = ctx.Response().Json(401, contractshttp.Json{"error": "unauthorized"}).Abort()
		return
	}
	ctx.WithContext(oidc.WithBrowser(ctx.Context(), b))
	ctx.Request().Next()
}

// ProtectOIDC accepts only an access token issued by this provider for the
// explicit audience. ID tokens and personal API tokens are not accepted.
func ProtectOIDC(guard, audience string, scopes ...string) []contractshttp.Middleware {
	p, err := NewOIDCProvider()
	if err != nil {
		panic(err)
	}
	if p != nil && OIDCProviderConfig().Guard != guard {
		panic("OIDC provider guard mismatch")
	}
	return []contractshttp.Middleware{middleware.OIDCAuthenticated(guard, audience, p, scopes...)}
}

// ProtectSessionOrOIDC preserves browser CSRF protection and never falls back to
// a cookie when any Authorization header was supplied.
func ProtectSessionOrOIDC(guard, audience string, scopes ...string) []contractshttp.Middleware {
	chain := Protect(guard)
	wrapped := make([]contractshttp.Middleware, 0, len(chain)+1)
	for i, m := range chain {
		wrapped = append(wrapped, middleware.UnlessBearer(m, fmt.Sprintf("%s.oidc.%d", guard, i)))
	}
	bearer := ProtectOIDC(guard, audience, scopes...)[0]
	return append(wrapped, &oidcBearerOnly{inner: bearer, guard: guard})
}

type oidcBearerOnly struct {
	inner contractshttp.Middleware
	guard string
}

func (m *oidcBearerOnly) Signature() string { return "authkit.oidc.optional-bearer." + m.guard }
func (m *oidcBearerOnly) Handle(ctx contractshttp.Context) {
	if strings.TrimSpace(ctx.Request().Header("Authorization")) != "" {
		m.inner.Handle(ctx)
		return
	}
	ctx.Request().Next()
}
