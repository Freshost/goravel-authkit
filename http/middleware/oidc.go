package middleware

import (
	"errors"
	"net/http"
	"strings"

	"github.com/freshost/goravel-authkit/helpers"
	"github.com/freshost/goravel-authkit/oidc"
	contractshttp "github.com/goravel/framework/contracts/http"
)

func OIDCAuthenticated(guard, audience string, provider *oidc.Provider, scopes ...string) contractshttp.Middleware {
	return &oidcAuthenticatedMiddleware{guard: guard, audience: audience, provider: provider, scopes: append([]string(nil), scopes...)}
}

type oidcAuthenticatedMiddleware struct {
	guard, audience string
	provider        *oidc.Provider
	scopes          []string
}

func (m *oidcAuthenticatedMiddleware) Signature() string {
	return "authkit.oidc.bearer." + m.guard + "." + m.audience + "." + strings.Join(m.scopes, ",")
}
func (m *oidcAuthenticatedMiddleware) Handle(ctx contractshttp.Context) {
	value, ok := bearerToken(ctx.Request().Header("Authorization"))
	if !ok || m.provider == nil {
		abortBearer(ctx, http.StatusUnauthorized, "invalid_token", "A valid access token is required", "")
		return
	}
	identity, err := m.provider.ResolveAccessToken(ctx.Context(), value, m.audience, m.scopes...)
	if err != nil {
		if oidc.IsAuthenticationError(err) {
			abortBearer(ctx, http.StatusUnauthorized, "invalid_token", "A valid access token is required", "")
			return
		}
		if errors.Is(err, oidc.ErrForbidden) {
			abortBearer(ctx, http.StatusForbidden, "insufficient_scope", "The access token is not authorized for this resource", strings.Join(m.scopes, " "))
			return
		}
		_ = ctx.Response().Json(http.StatusServiceUnavailable, contractshttp.Json{"error": "temporarily_unavailable"}).Abort()
		return
	}
	ctx.WithValue(helpers.CtxAuthUserID, identity.UserID.String())
	ctx.WithValue(helpers.CtxAuthMethod, "oidc")
	ctx.WithValue(helpers.CtxOIDCClientID, identity.ClientID)
	ctx.WithValue(helpers.CtxOIDCConnectionID, identity.ConnectionID)
	ctx.WithValue(helpers.CtxOIDCScopes, identity.Scopes)
	ctx.Request().Next()
}
