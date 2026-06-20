// Package middleware holds the goravel-auth HTTP middleware: the session guard
// (Authenticated) and the login rate-limiter (RateLimitAuth).
package middleware

import (
	nethttp "net/http"
	"time"

	"github.com/google/uuid"
	contractshttp "github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"github.com/freshost/goravel-auth/helpers"
	"github.com/freshost/goravel-auth/models"
)

// SessionKeyPasswordChangedAt holds the users.password_changed_at value captured
// at login. Authenticated compares it with the fresh DB value to invalidate
// every OTHER session after a password change. The authenticated user id itself
// is owned by Goravel's integrated auth guard, not written here.
const SessionKeyPasswordChangedAt = "password_changed_at"

// FormatPasswordTimestamp renders a password_changed_at value in the canonical
// form stored in the session. Exported so the login handler stamps it in the
// same format Authenticated compares against.
func FormatPasswordTimestamp(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

// Authenticated guards routes behind the named session guard. It:
//  1. loads the user via the integrated auth guard (401 on miss / deleted user),
//  2. compares the login-stamped password_changed_at with the DB value — a
//     mismatch means the password changed after this session was issued, so
//     this (older) session is logged out (401),
//  3. injects the user id into the request context (helpers.CtxAuthUserID).
func Authenticated(guard string) contractshttp.Middleware {
	return func(ctx contractshttp.Context) {
		var user models.User
		if err := facades.Auth(ctx).Guard(guard).User(&user); err != nil || user.ID == uuid.Nil {
			abortUnauthorized(ctx, "unauthorized", "Authentication required")
			return
		}

		session := ctx.Request().Session()
		if session != nil && !sessionPasswordTimestampValid(session, user.PasswordChangedAt) {
			_ = facades.Auth(ctx).Guard(guard).Logout()
			session.Forget(SessionKeyPasswordChangedAt)
			abortUnauthorized(ctx, "session_expired", "Please log in again")
			return
		}

		ctx.WithValue(helpers.CtxAuthUserID, user.ID.String())
		ctx.Request().Next()
	}
}

// RequireRole rejects authenticated users whose role is not in allowed. It must
// run AFTER Authenticated. An empty allowed list is a no-op (open to any
// authenticated user) — this is the v1 default, since v1 ships no RBAC. Apps
// that want to gate user-management behind a role pass one or more roles via
// routes.Options.UserManagementRoles.
func RequireRole(guard string, allowed ...string) contractshttp.Middleware {
	return func(ctx contractshttp.Context) {
		if len(allowed) == 0 {
			ctx.Request().Next()
			return
		}
		var user models.User
		if err := facades.Auth(ctx).Guard(guard).User(&user); err != nil || user.ID == uuid.Nil {
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
}

func abortUnauthorized(ctx contractshttp.Context, code, message string) {
	_ = ctx.Response().Json(nethttp.StatusUnauthorized, contractshttp.Json{
		"error":   code,
		"message": message,
	}).Abort()
}

func sessionPasswordTimestampValid(session interface {
	Get(key string, defaultValue ...any) any
}, dbValue time.Time) bool {
	stored, ok := session.Get(SessionKeyPasswordChangedAt).(string)
	if !ok || stored == "" {
		return false
	}
	return stored == FormatPasswordTimestamp(dbValue)
}
