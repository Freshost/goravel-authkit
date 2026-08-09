// Package middleware holds the goravel-authkit HTTP middleware: the session guard
// (Authenticated) and the login rate-limiter (RateLimitAuth).
package middleware

import (
	nethttp "net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	contractshttp "github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"github.com/freshost/goravel-authkit/helpers"
	"github.com/freshost/goravel-authkit/repositories"
)

// The authenticated user id is owned by Goravel's session guard (auth_<guard>_id);
// authkit reads it via helpers.GuardUserID and loads the user record through its
// own table-aware repository, so each instance resolves its own table.
//
// The login-stamped password_changed_at lives under helpers.PasswordChangedAtKey(guard)
// (namespaced per guard so two instances can share one session cookie).
// Authenticated compares it with the fresh DB value to invalidate every OTHER
// session after a password change.

// FormatPasswordTimestamp renders a password_changed_at value in the canonical
// form stored in the session. Exported so the login handler stamps it in the
// same format Authenticated compares against.
func FormatPasswordTimestamp(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

// Authenticated guards routes behind the named session guard. It:
//  1. resolves the session's user id (401 on no session) and loads the user from
//     the instance's table (401 on a deleted user),
//  2. compares the login-stamped password_changed_at with the DB value — a
//     mismatch means the password changed after this session was issued, so
//     this (older) session is logged out (401),
//  3. injects the user id into the request context (helpers.CtxAuthUserID).
func Authenticated(guard string, users repositories.UsersRepository) contractshttp.Middleware {
	return &authenticatedMiddleware{guard: guard, users: users}
}

type authenticatedMiddleware struct {
	guard string
	users repositories.UsersRepository
}

func (middleware *authenticatedMiddleware) Handle(ctx contractshttp.Context) {
	guard := middleware.guard
	users := middleware.users
	id := helpers.GuardUserID(ctx, guard)
	if id == uuid.Nil {
		abortUnauthorized(ctx, "unauthorized", "Authentication required")
		return
	}
	user, err := users.FindByID(ctx.Context(), id)
	if err != nil || user == nil {
		abortUnauthorized(ctx, "unauthorized", "Authentication required")
		return
	}

	if user.IsDisabled() {
		_ = facades.Auth(ctx).Guard(guard).Logout()
		abortUnauthorized(ctx, "account_disabled", "This account has been disabled")
		return
	}

	session := ctx.Request().Session()
	pwKey := helpers.PasswordChangedAtKey(guard)
	if session != nil && !sessionPasswordTimestampValid(session, pwKey, user.PasswordChangedAt) {
		_ = facades.Auth(ctx).Guard(guard).Logout()
		session.Forget(pwKey)
		abortUnauthorized(ctx, "session_expired", "Please log in again")
		return
	}

	ctx.WithValue(helpers.CtxAuthUserID, user.ID.String())
	ctx.Request().Next()
}

func (middleware *authenticatedMiddleware) Signature() string {
	return "goravel-authkit.authenticated." + middleware.guard
}

// RequireRole rejects authenticated users whose role is not in allowed. It must
// run AFTER Authenticated. The /users routes are always mounted with a non-empty
// allow-list (defaulting to "admin", fail-closed), so this gate is real for
// them. An empty allowed list is a defensive no-op; callers should never pass
// one for a route that must be protected.
func RequireRole(guard string, users repositories.UsersRepository, allowed ...string) contractshttp.Middleware {
	return &requireRoleMiddleware{guard: guard, users: users, allowed: allowed}
}

type requireRoleMiddleware struct {
	guard   string
	users   repositories.UsersRepository
	allowed []string
}

func (middleware *requireRoleMiddleware) Handle(ctx contractshttp.Context) {
	users := middleware.users
	allowed := middleware.allowed
	if len(allowed) == 0 {
		ctx.Request().Next()
		return
	}
	// Runs after Authenticated, which injected the user id; load the user from
	// the guard's table to read the role.
	id := helpers.AuthUserID(ctx)
	if id == uuid.Nil {
		abortUnauthorized(ctx, "unauthorized", "Authentication required")
		return
	}
	user, err := users.FindByID(ctx.Context(), id)
	if err != nil || user == nil {
		abortUnauthorized(ctx, "unauthorized", "Authentication required")
		return
	}
	for _, role := range allowed {
		if user.Role == role {
			ctx.Request().Next()
			return
		}
	}
	_ = ctx.Response().Json(nethttp.StatusForbidden, contractshttp.Json{
		"error":   "forbidden",
		"message": "Insufficient permissions",
	}).Abort()
}

func (middleware *requireRoleMiddleware) Signature() string {
	return "goravel-authkit.require-role." + middleware.guard + "." + strings.Join(middleware.allowed, ",")
}

func abortUnauthorized(ctx contractshttp.Context, code, message string) {
	_ = ctx.Response().Json(nethttp.StatusUnauthorized, contractshttp.Json{
		"error":   code,
		"message": message,
	}).Abort()
}

func sessionPasswordTimestampValid(session interface {
	Get(key string, defaultValue ...any) any
}, key string, dbValue time.Time) bool {
	stored, ok := session.Get(key).(string)
	if !ok || stored == "" {
		return false
	}
	return stored == FormatPasswordTimestamp(dbValue)
}
