package controllers

import (
	"errors"
	"net/http"

	"github.com/google/uuid"
	contractshttp "github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"github.com/freshost/goravel-authkit/contracts"
	"github.com/freshost/goravel-authkit/helpers"
	"github.com/freshost/goravel-authkit/http/middleware"
	"github.com/freshost/goravel-authkit/http/responses"
	"github.com/freshost/goravel-authkit/repositories"
	"github.com/freshost/goravel-authkit/services"
)

// ImpersonationController handles user impersonation: an authorized actor switches
// into another user's session — within its own guard or across guards — and back.
// The session records the impersonator (under helpers.ImpersonatorKey) so the
// switch is reversible and auditable; no remember cookie is issued, so it is
// ephemeral. It relies on the multi-guard shared session: a cross-guard switch
// adds the target guard's session alongside the actor's, so "stop" simply drops it.
type ImpersonationController struct {
	guard       string            // the guard this controller is mounted on
	guardTables map[string]string // guard -> users table, to load users in any target guard
	gate        *services.Impersonation
	audit       *services.Audit // nil when audit logging is disabled
}

// NewImpersonationController builds the controller. guardTables maps every
// configured guard to its users table so a target in any guard can be loaded.
func NewImpersonationController(guard string, guardTables map[string]string, gate *services.Impersonation, audit *services.Audit) *ImpersonationController {
	return &ImpersonationController{guard: guard, guardTables: guardTables, gate: gate, audit: audit}
}

func (c *ImpersonationController) repo(guard string) repositories.UsersRepository {
	return repositories.NewUsersWithTable(c.guardTables[guard])
}

// Start switches the current actor into the target user's session. Handles
// POST {prefix}/auth/impersonate.
func (c *ImpersonationController) Start(ctx contractshttp.Context) contractshttp.Response {
	stdctx := ctx.Context()
	actorID := helpers.AuthUserID(ctx)
	if actorID == uuid.Nil {
		return c.unauthorized(ctx)
	}
	actor, err := c.repo(c.guard).FindByID(stdctx, actorID)
	if err != nil || actor == nil {
		return c.unauthorized(ctx)
	}

	var req responses.ImpersonateRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return c.badRequest(ctx, "Invalid request body")
	}
	targetGuard := req.Guard
	if targetGuard == "" {
		targetGuard = c.guard
	}
	targetID, err := uuid.Parse(req.UserID)
	if err != nil || targetID == uuid.Nil {
		return c.badRequest(ctx, "A valid userId is required")
	}
	if _, ok := c.guardTables[targetGuard]; !ok {
		return c.badRequest(ctx, "Unknown guard")
	}
	if targetGuard == c.guard && targetID == actorID {
		return c.badRequest(ctx, "Cannot impersonate yourself")
	}
	// One impersonation per guard at a time.
	if _, already := helpers.Impersonator(ctx, targetGuard); already {
		return ctx.Response().Json(http.StatusConflict, responses.ErrorResponse{
			Error: "already_impersonating", Message: "Already impersonating in this guard",
		})
	}

	target, err := c.repo(targetGuard).FindByID(stdctx, targetID)
	if err != nil {
		return c.internal(ctx)
	}
	if target == nil {
		return ctx.Response().Json(http.StatusNotFound, responses.ErrorResponse{
			Error: "not_found", Message: "Target user not found",
		})
	}
	if target.IsDisabled() {
		return ctx.Response().Json(http.StatusForbidden, responses.ErrorResponse{
			Error: "account_disabled", Message: "Cannot impersonate a disabled account",
		})
	}

	actorP := contracts.Principal{Guard: c.guard, UserID: actor.ID, Email: actor.Email, Role: actor.Role}
	targetP := contracts.Principal{Guard: targetGuard, UserID: target.ID, Email: target.Email, Role: target.Role}
	if err := c.gate.Authorize(stdctx, actorP, targetGuard, targetP); err != nil {
		return c.mapGateError(ctx, err)
	}

	sameGuard := targetGuard == c.guard
	if _, err := facades.Auth(ctx).Guard(targetGuard).Login(target); err != nil {
		facades.Log().Errorf("impersonate: establish session: %v", err)
		return c.internal(ctx)
	}
	helpers.SetImpersonator(ctx, targetGuard, helpers.ImpersonatorMarker{
		Guard: c.guard, UserID: actor.ID, Email: actor.Email, SameGuard: sameGuard,
	})
	if err := helpers.RegenerateAndPersistSession(ctx); err != nil {
		facades.Log().Errorf("impersonate: regenerate session: %v", err)
	}
	if sess := ctx.Request().Session(); sess != nil {
		sess.Put(helpers.PasswordChangedAtKey(targetGuard), middleware.FormatPasswordTimestamp(target.PasswordChangedAt))
	}
	// Intentionally no remember cookie and no active-session tracking token:
	// impersonation is ephemeral and must not be restorable from a persistent cookie.

	c.writeAudit(ctx, actor.ID, target.ID, targetGuard, "auth.impersonation_started")

	resp := responses.NewUserResponse(target)
	resp.ImpersonatedBy = &responses.ImpersonatorRef{Guard: c.guard, ID: actor.ID.String(), Email: actor.Email}
	return ctx.Response().Json(http.StatusOK, resp)
}

// Stop ends the impersonation on this guard and restores the actor. Handles
// POST {prefix}/auth/impersonate/stop.
func (c *ImpersonationController) Stop(ctx contractshttp.Context) contractshttp.Response {
	stdctx := ctx.Context()
	marker, ok := helpers.Impersonator(ctx, c.guard)
	if !ok {
		return c.badRequest(ctx, "Not impersonating")
	}
	targetID := helpers.AuthUserID(ctx) // the impersonated user, for the audit trail

	if marker.SameGuard {
		// Restore the original actor as this guard's user.
		actor, err := c.repo(marker.Guard).FindByID(stdctx, marker.UserID)
		if err == nil && actor != nil {
			if _, err := facades.Auth(ctx).Guard(c.guard).Login(actor); err != nil {
				facades.Log().Errorf("impersonate stop: restore session: %v", err)
				return c.internal(ctx)
			}
			if sess := ctx.Request().Session(); sess != nil {
				sess.Put(helpers.PasswordChangedAtKey(c.guard), middleware.FormatPasswordTimestamp(actor.PasswordChangedAt))
			}
		} else {
			// Original actor is gone: sign out rather than leave a dangling session.
			_ = facades.Auth(ctx).Guard(c.guard).Logout()
			if sess := ctx.Request().Session(); sess != nil {
				sess.Forget(helpers.PasswordChangedAtKey(c.guard))
			}
		}
	} else {
		// Cross-guard: drop this guard's session; the actor's own guard session (a
		// different key in the shared cookie) is untouched.
		_ = facades.Auth(ctx).Guard(c.guard).Logout()
		if sess := ctx.Request().Session(); sess != nil {
			sess.Forget(helpers.PasswordChangedAtKey(c.guard))
		}
	}

	helpers.ClearImpersonator(ctx, c.guard)
	if err := helpers.RegenerateAndPersistSession(ctx); err != nil {
		facades.Log().Errorf("impersonate stop: regenerate session: %v", err)
	}
	c.writeAudit(ctx, marker.UserID, targetID, c.guard, "auth.impersonation_stopped")
	return ctx.Response().Json(http.StatusOK, responses.MessageResponse{Message: "Impersonation ended"})
}

func (c *ImpersonationController) mapGateError(ctx contractshttp.Context, err error) contractshttp.Response {
	if errors.Is(err, services.ErrForbidden) {
		return ctx.Response().Json(http.StatusForbidden, responses.ErrorResponse{
			Error: "forbidden", Message: "You are not allowed to impersonate this user",
		})
	}
	facades.Log().Errorf("impersonate authorize: %v", err)
	return c.internal(ctx)
}

func (c *ImpersonationController) writeAudit(ctx contractshttp.Context, actorID, targetID uuid.UUID, targetGuard, action string) {
	if c.audit == nil {
		return
	}
	aid := actorID
	rid := targetID.String()
	if err := c.audit.Log(ctx.Context(), services.AuditEntry{
		ActorID:      &aid,
		Action:       action,
		ResourceType: "user",
		ResourceID:   &rid,
		Metadata:     map[string]any{"actor_guard": c.guard, "target_guard": targetGuard},
		IP:           ctx.Request().Ip(),
	}); err != nil {
		facades.Log().Errorf("audit %s: %v", action, err)
	}
}

func (c *ImpersonationController) unauthorized(ctx contractshttp.Context) contractshttp.Response {
	return ctx.Response().Json(http.StatusUnauthorized, responses.ErrorResponse{
		Error: "unauthorized", Message: "Authentication required",
	})
}

func (c *ImpersonationController) badRequest(ctx contractshttp.Context, msg string) contractshttp.Response {
	return ctx.Response().Json(http.StatusBadRequest, responses.ErrorResponse{
		Error: "validation_error", Message: msg,
	})
}

func (c *ImpersonationController) internal(ctx contractshttp.Context) contractshttp.Response {
	return ctx.Response().Json(http.StatusInternalServerError, responses.ErrorResponse{
		Error: "internal_error", Message: "Internal server error",
	})
}
