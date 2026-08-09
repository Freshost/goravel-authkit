package middleware

import (
	nethttp "net/http"

	contractshttp "github.com/goravel/framework/contracts/http"

	"github.com/freshost/goravel-authkit/helpers"
)

// RejectWhileImpersonating blocks an action when the session under guard is an
// impersonated one. It guards the credential- and privilege-sensitive routes
// (password change, user management, and starting another impersonation) so an
// actor acting "as" a user cannot change that user's password, manage users, or
// chain into a nested impersonation. It is a no-op for ordinary sessions.
func RejectWhileImpersonating(guard string) contractshttp.Middleware {
	return &rejectWhileImpersonatingMiddleware{guard: guard}
}

type rejectWhileImpersonatingMiddleware struct {
	guard string
}

func (middleware *rejectWhileImpersonatingMiddleware) Handle(ctx contractshttp.Context) {
	if helpers.IsImpersonating(ctx, middleware.guard) {
		_ = ctx.Response().Json(nethttp.StatusForbidden, contractshttp.Json{
			"error":   "impersonation_forbidden",
			"message": "This action is not allowed while impersonating",
		}).Abort()
		return
	}
	ctx.Request().Next()
}

func (middleware *rejectWhileImpersonatingMiddleware) Signature() string {
	return "goravel-authkit.reject-while-impersonating." + middleware.guard
}
