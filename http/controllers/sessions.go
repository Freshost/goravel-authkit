package controllers

import (
	"errors"
	"net/http"

	"github.com/google/uuid"
	contractshttp "github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"github.com/freshost/goravel-authkit/helpers"
	"github.com/freshost/goravel-authkit/http/responses"
	"github.com/freshost/goravel-authkit/services"
)

// SessionsController exposes the current user's active sessions and lets them
// terminate individual sessions or every session other than the current one.
type SessionsController struct {
	sessions *services.Sessions
	audit    *services.Audit
	guard    string
}

// NewSessionsController builds the sessions controller.
func NewSessionsController(sessions *services.Sessions, audit *services.Audit, guard string) *SessionsController {
	return &SessionsController{sessions: sessions, audit: audit, guard: guard}
}

// currentToken is the active-session tracking token of the request's session —
// the value the tracking rows are keyed by, used to flag/skip the current session.
func (c *SessionsController) currentToken(ctx contractshttp.Context) string {
	return helpers.SessionTrackingToken(ctx, c.guard)
}

// Index returns the current user's active sessions, most recent first, with the
// current session flagged. Handles GET {prefix}/auth/sessions.
func (c *SessionsController) Index(ctx contractshttp.Context) contractshttp.Response {
	userID := helpers.AuthUserID(ctx)
	views, err := c.sessions.List(ctx.Request().Origin().Context(), userID, c.currentToken(ctx))
	if err != nil {
		return c.internal(ctx)
	}
	return ctx.Response().Json(http.StatusOK, responses.NewSessionListResponse(views))
}

// Destroy signs out one of the current user's other sessions by id. The current
// session cannot be terminated here (use logout). Handles
// DELETE {prefix}/auth/sessions/{id}.
func (c *SessionsController) Destroy(ctx contractshttp.Context) contractshttp.Response {
	id, errResp := helpers.ParseUUIDParam(ctx, "id")
	if errResp != nil {
		return *errResp
	}
	userID := helpers.AuthUserID(ctx)
	err := c.sessions.Terminate(ctx.Request().Origin().Context(), userID, id, c.currentToken(ctx))
	switch {
	case err == nil:
		c.writeAudit(ctx, &userID, "auth.session_terminated", id.String())
		return ctx.Response().Json(http.StatusOK, responses.MessageResponse{Message: "Session terminated"})
	case errors.Is(err, services.ErrNotFound):
		return ctx.Response().Json(http.StatusNotFound, responses.ErrorResponse{
			Error: "not_found", Message: "Session not found",
		})
	case errors.Is(err, services.ErrValidation):
		return ctx.Response().Json(http.StatusBadRequest, responses.ErrorResponse{
			Error: "current_session", Message: "Use logout to end the current session",
		})
	default:
		return c.internal(ctx)
	}
}

// DestroyOthers terminates every session for the current user except the current
// one. Handles DELETE {prefix}/auth/sessions.
func (c *SessionsController) DestroyOthers(ctx contractshttp.Context) contractshttp.Response {
	userID := helpers.AuthUserID(ctx)
	if err := c.sessions.TerminateOthers(ctx.Request().Origin().Context(), userID, c.currentToken(ctx)); err != nil {
		return c.internal(ctx)
	}
	c.writeAudit(ctx, &userID, "auth.sessions_terminated_others", userID.String())
	return ctx.Response().Json(http.StatusOK, responses.MessageResponse{Message: "Other sessions signed out"})
}

func (c *SessionsController) writeAudit(ctx contractshttp.Context, actorID *uuid.UUID, action, resourceID string) {
	if c.audit == nil {
		return
	}
	rid := resourceID
	if err := c.audit.Log(ctx.Request().Origin().Context(), services.AuditEntry{
		ActorID:      actorID,
		Action:       action,
		ResourceType: "session",
		ResourceID:   &rid,
		IP:           ctx.Request().Ip(),
	}); err != nil {
		facades.Log().Errorf("audit %s: %v", action, err)
	}
}

func (c *SessionsController) internal(ctx contractshttp.Context) contractshttp.Response {
	return ctx.Response().Json(http.StatusInternalServerError, responses.ErrorResponse{
		Error: "internal_error", Message: "Internal server error",
	})
}
