package middleware

import (
	"errors"
	nethttp "net/http"

	contractshttp "github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"github.com/freshost/goravel-authkit/contracts"
	"github.com/freshost/goravel-authkit/helpers"
	"github.com/freshost/goravel-authkit/repositories"
	"github.com/freshost/goravel-authkit/services"
)

// ValidateImpersonationSession re-applies the actor guard's current
// impersonation policy while a session is switched into targetGuard. Disabling,
// deleting, or demoting the actor (or changing the host policy) therefore takes
// effect on the next request instead of leaving an already-open impersonation
// session authorized indefinitely.
func ValidateImpersonationSession(targetGuard string, users map[string]repositories.UsersRepository, gates map[string]*services.Impersonation) contractshttp.Middleware {
	return &validateImpersonationSessionMiddleware{targetGuard: targetGuard, users: users, gates: gates}
}

type validateImpersonationSessionMiddleware struct {
	targetGuard string
	users       map[string]repositories.UsersRepository
	gates       map[string]*services.Impersonation
}

func (middleware *validateImpersonationSessionMiddleware) Handle(ctx contractshttp.Context) {
	marker, ok := helpers.Impersonator(ctx, middleware.targetGuard)
	if !ok {
		ctx.Request().Next()
		return
	}
	actorRepo := middleware.users[marker.Guard]
	targetRepo := middleware.users[middleware.targetGuard]
	gate := middleware.gates[marker.Guard]
	if actorRepo == nil || targetRepo == nil || gate == nil {
		middleware.revoke(ctx)
		return
	}

	actor, err := actorRepo.FindByID(ctx.Context(), marker.UserID)
	if err != nil {
		middleware.unavailable(ctx, err)
		return
	}
	targetID := helpers.AuthUserID(ctx)
	target, err := targetRepo.FindByID(ctx.Context(), targetID)
	if err != nil {
		middleware.unavailable(ctx, err)
		return
	}
	if actor == nil || actor.IsDisabled() || target == nil || target.IsDisabled() {
		middleware.revoke(ctx)
		return
	}

	actorPrincipal := contracts.Principal{Guard: marker.Guard, UserID: actor.ID, Email: actor.Email, Role: actor.Role}
	targetPrincipal := contracts.Principal{Guard: middleware.targetGuard, UserID: target.ID, Email: target.Email, Role: target.Role}
	if err := gate.Authorize(ctx.Context(), actorPrincipal, middleware.targetGuard, targetPrincipal); err != nil {
		if errors.Is(err, services.ErrInternal) {
			middleware.unavailable(ctx, err)
			return
		}
		middleware.revoke(ctx)
		return
	}

	ctx.Request().Next()
}

func (middleware *validateImpersonationSessionMiddleware) revoke(ctx contractshttp.Context) {
	_ = facades.Auth(ctx).Guard(middleware.targetGuard).Logout()
	helpers.ClearImpersonator(ctx, middleware.targetGuard)
	if sess := ctx.Request().Session(); sess != nil {
		sess.Forget(helpers.PasswordChangedAtKey(middleware.targetGuard))
	}
	if err := helpers.RegenerateAndPersistSession(ctx); err != nil {
		facades.Log().Errorf("impersonation validation: regenerate session: %v", err)
	}
	_ = ctx.Response().Json(nethttp.StatusForbidden, contractshttp.Json{
		"error": "impersonation_revoked", "message": "Impersonation is no longer authorized",
	}).Abort()
}

func (middleware *validateImpersonationSessionMiddleware) unavailable(ctx contractshttp.Context, err error) {
	facades.Log().Errorf("impersonation validation: %v", err)
	_ = ctx.Response().Json(nethttp.StatusServiceUnavailable, contractshttp.Json{
		"error": "authentication_unavailable", "message": "Authentication service unavailable",
	}).Abort()
}

func (middleware *validateImpersonationSessionMiddleware) Signature() string {
	return "goravel-authkit.validate-impersonation." + middleware.targetGuard
}
