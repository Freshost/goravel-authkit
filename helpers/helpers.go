// Package helpers holds small HTTP utilities shared by the goravel-authkit
// controllers and middleware: route-param parsing, the authenticated-user
// context key, and the session-regeneration workaround.
package helpers

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"slices"

	"github.com/google/uuid"
	contractshttp "github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"
)

// CtxAuthUserID is the request-context key under which the Authenticated
// middleware stores the current user id (string). Domain controllers read it
// via AuthUserID to scope queries by the current user.
const CtxAuthUserID = "auth_user_id"

const (
	CtxAuthMethod     = "auth_method"
	CtxAPITokenID     = "auth_api_token_id"
	CtxAPITokenScopes = "auth_api_token_scopes"

	AuthMethodSession  = "session"
	AuthMethodAPIToken = "api_token"
)

// ParseUUIDParam parses a UUID route parameter. On failure it returns a pointer
// to a 400 response the controller returns directly:
//
//	id, errResp := helpers.ParseUUIDParam(ctx, "id")
//	if errResp != nil { return *errResp }
func ParseUUIDParam(ctx contractshttp.Context, name string) (uuid.UUID, *contractshttp.Response) {
	raw := ctx.Request().Route(name)
	id, err := uuid.Parse(raw)
	if err != nil {
		var resp contractshttp.Response = ctx.Response().Json(http.StatusBadRequest, contractshttp.Json{
			"error":   "invalid_id",
			"message": "Invalid ID parameter: " + name,
		})
		return uuid.Nil, &resp
	}
	return id, nil
}

// NewSessionToken returns a fresh random token for active-session tracking (256
// bits, hex). An empty string is returned only if the system RNG fails, in which
// case the session is simply not tracked (the tracking layer treats "" as absent).
func NewSessionToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

// SessionTrackingToken reads the active-session tracking token for the given
// guard from the current session, or "" when there is none.
func SessionTrackingToken(ctx contractshttp.Context, guard string) string {
	sess := ctx.Request().Session()
	if sess == nil {
		return ""
	}
	token, _ := sess.Get(SessionTrackingTokenKey(guard)).(string)
	return token
}

// GuardUserID returns the id of the user authenticated under the given guard,
// read from the session via Goravel's session guard (the auth_<guard>_id key).
// It returns uuid.Nil when there is no authenticated session. authkit then loads
// the user record itself through its table-aware repository, so the table is
// resolved per instance rather than by Goravel's model-bound user provider.
func GuardUserID(ctx contractshttp.Context, guard string) uuid.UUID {
	idStr, err := facades.Auth(ctx).Guard(guard).ID()
	if err != nil || idStr == "" {
		return uuid.Nil
	}
	id, err := uuid.Parse(idStr)
	if err != nil {
		return uuid.Nil
	}
	return id
}

// AuthUserID reads the user id injected by the Authenticated middleware under
// CtxAuthUserID. It returns uuid.Nil when absent or unparseable.
func AuthUserID(ctx contractshttp.Context) uuid.UUID {
	raw, ok := ctx.Value(CtxAuthUserID).(string)
	if !ok {
		return uuid.Nil
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil
	}
	return id
}

// AuthMethod reports how the current request was authenticated. An empty value
// means no Authkit middleware established an identity.
func AuthMethod(ctx contractshttp.Context) string {
	method, _ := ctx.Value(CtxAuthMethod).(string)
	return method
}

// APITokenID returns the personal access token used for this request, or
// uuid.Nil for session-authenticated and unauthenticated requests.
func APITokenID(ctx contractshttp.Context) uuid.UUID {
	raw, _ := ctx.Value(CtxAPITokenID).(string)
	id, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil
	}
	return id
}

// APITokenScopes returns a copy of the scopes attached to the current token.
func APITokenScopes(ctx contractshttp.Context) []string {
	scopes, _ := ctx.Value(CtxAPITokenScopes).([]string)
	return slices.Clone(scopes)
}

// TokenCan reports whether a bearer-authenticated request has the given scope.
// Session authentication is deliberately not scope-limited and returns false.
func TokenCan(ctx contractshttp.Context, scope string) bool {
	return AuthMethod(ctx) == AuthMethodAPIToken && slices.Contains(APITokenScopes(ctx), scope)
}

// RegenerateAndPersistSession regenerates the session id (session-fixation
// protection) and RE-EMITS the cookie with the new id.
//
// Goravel's StartSession middleware writes the response Set-Cookie with the
// session id BEFORE the handler runs, so a plain session.Regenerate() inside the
// handler would save the auth under the NEW id while the browser keeps the OLD
// id. We therefore emit a second Set-Cookie with the new id (the later one wins).
func RegenerateAndPersistSession(ctx contractshttp.Context) error {
	session := ctx.Request().Session()
	if session == nil {
		return nil
	}
	if err := session.Regenerate(); err != nil {
		return err
	}

	config := facades.Config()
	ctx.Response().Cookie(contractshttp.Cookie{
		Name:     config.GetString("session.cookie"),
		Value:    session.GetID(),
		Path:     config.GetString("session.path", "/"),
		Domain:   config.GetString("session.domain"),
		MaxAge:   config.GetInt("session.lifetime", 120) * 60,
		Secure:   config.GetBool("session.secure", false),
		HttpOnly: config.GetBool("session.http_only", true),
		SameSite: config.GetString("session.same_site", "lax"),
	})
	return nil
}
