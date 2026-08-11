package middleware

import (
	"errors"
	nethttp "net/http"
	"slices"
	"strings"

	contractshttp "github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"github.com/freshost/goravel-authkit/helpers"
	"github.com/freshost/goravel-authkit/repositories"
	"github.com/freshost/goravel-authkit/services"
)

// BearerAuthenticated authenticates an opaque Authkit API token and optionally
// requires token scopes. Live user state is checked on every request, so deleting
// or disabling the owner immediately denies the token.
func BearerAuthenticated(guard string, tokens *services.APITokens, users repositories.UsersRepository, requiredScopes ...string) contractshttp.Middleware {
	return &bearerAuthenticatedMiddleware{guard: guard, tokens: tokens, users: users, requiredScopes: slices.Clone(requiredScopes)}
}

type bearerAuthenticatedMiddleware struct {
	guard          string
	tokens         *services.APITokens
	users          repositories.UsersRepository
	requiredScopes []string
}

func (middleware *bearerAuthenticatedMiddleware) Handle(ctx contractshttp.Context) {
	if middleware.tokens == nil {
		abortBearer(ctx, nethttp.StatusUnauthorized, "invalid_token", "A valid bearer token is required", "")
		return
	}
	plaintext, ok := bearerToken(ctx.Request().Header("Authorization"))
	if !ok {
		abortBearer(ctx, nethttp.StatusUnauthorized, "invalid_token", "A valid bearer token is required", "")
		return
	}
	token, err := middleware.tokens.Resolve(ctx.Context(), plaintext)
	if err != nil {
		if errors.Is(err, services.ErrInvalidAPIToken) {
			abortBearer(ctx, nethttp.StatusUnauthorized, "invalid_token", "A valid bearer token is required", "")
			return
		}
		facades.Log().Errorf("authkit api token authentication: %v", err)
		_ = ctx.Response().Json(nethttp.StatusServiceUnavailable, contractshttp.Json{
			"error": "authentication_unavailable", "message": "Authentication service unavailable",
		}).Abort()
		return
	}
	user, err := middleware.users.FindByID(ctx.Context(), token.UserID)
	if err != nil {
		facades.Log().Errorf("authkit api token user lookup: %v", err)
		_ = ctx.Response().Json(nethttp.StatusServiceUnavailable, contractshttp.Json{
			"error": "authentication_unavailable", "message": "Authentication service unavailable",
		}).Abort()
		return
	}
	if user == nil || user.IsDisabled() {
		abortBearer(ctx, nethttp.StatusUnauthorized, "invalid_token", "A valid bearer token is required", "")
		return
	}
	for _, required := range middleware.requiredScopes {
		if !slices.Contains([]string(token.Scopes), required) {
			abortBearer(ctx, nethttp.StatusForbidden, "insufficient_scope", "The token does not have the required scope", strings.Join(middleware.requiredScopes, " "))
			return
		}
	}

	ctx.WithValue(helpers.CtxAuthUserID, user.ID.String())
	ctx.WithValue(helpers.CtxAuthMethod, helpers.AuthMethodAPIToken)
	ctx.WithValue(helpers.CtxAPITokenID, token.ID.String())
	ctx.WithValue(helpers.CtxAPITokenScopes, []string(token.Scopes))
	ctx.Request().Next()
}

func (middleware *bearerAuthenticatedMiddleware) Signature() string {
	return "goravel-authkit.api-token." + middleware.guard + "." + strings.Join(middleware.requiredScopes, ",")
}

// AuthenticateAny uses bearer authentication whenever an Authorization header
// is present and otherwise falls back to the normal Authkit session guard. It
// never silently accepts a session after a malformed or invalid bearer token.
func AuthenticateAny(guard string, tokens *services.APITokens, users repositories.UsersRepository, requiredScopes ...string) contractshttp.Middleware {
	return &authenticateAnyMiddleware{
		guard:          guard,
		requiredScopes: slices.Clone(requiredScopes),
		bearer:         BearerAuthenticated(guard, tokens, users, requiredScopes...),
		session:        Authenticated(guard, users),
	}
}

type authenticateAnyMiddleware struct {
	guard          string
	bearer         contractshttp.Middleware
	session        contractshttp.Middleware
	requiredScopes []string
}

func (middleware *authenticateAnyMiddleware) Handle(ctx contractshttp.Context) {
	if strings.TrimSpace(ctx.Request().Header("Authorization")) != "" {
		middleware.bearer.Handle(ctx)
		return
	}
	middleware.session.Handle(ctx)
}

func (middleware *authenticateAnyMiddleware) Signature() string {
	return "goravel-authkit.authenticate-any." + middleware.guard + "." + strings.Join(middleware.requiredScopes, ",")
}

// UnlessBearer runs inner only when no Authorization header is present. It is
// used by hybrid routes to keep bearer requests stateless while preserving the
// normal session and CSRF middleware for browser requests.
func UnlessBearer(inner contractshttp.Middleware, signature string) contractshttp.Middleware {
	return &unlessBearerMiddleware{inner: inner, signature: signature}
}

type unlessBearerMiddleware struct {
	inner     contractshttp.Middleware
	signature string
}

func (middleware *unlessBearerMiddleware) Handle(ctx contractshttp.Context) {
	if strings.TrimSpace(ctx.Request().Header("Authorization")) != "" {
		ctx.Request().Next()
		return
	}
	middleware.inner.Handle(ctx)
}

func (middleware *unlessBearerMiddleware) Signature() string {
	return "goravel-authkit.unless-bearer." + middleware.signature
}

func bearerToken(header string) (string, bool) {
	parts := strings.Fields(header)
	returnValue := ""
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		returnValue = parts[1]
	}
	return returnValue, returnValue != ""
}

func abortBearer(ctx contractshttp.Context, status int, code, message, scope string) {
	challenge := `Bearer error="` + code + `"`
	if scope != "" {
		challenge += `, scope="` + scope + `"`
	}
	ctx.Response().Header("WWW-Authenticate", challenge)
	_ = ctx.Response().Json(status, contractshttp.Json{"error": code, "message": message}).Abort()
}
