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

func (c *SessionsController) currentSessionID(ctx contractshttp.Context) string {
	if s := ctx.Request().Session(); s != nil {
		return s.GetID()
	}
	return ""
}

// Index godoc
//
//	@ID				listSessions
//	@Summary		List active sessions
//	@Description	Returns the current user's active sessions (most recent first); the current session is flagged.
//	@Tags			Sessions
//	@Security		CookieAuth
//	@Produce		json
//	@Success		200	{array}		responses.SessionResponse
//	@Failure		401	{object}	responses.ErrorResponse
//	@Router			/auth/sessions [get]
func (c *SessionsController) Index(ctx contractshttp.Context) contractshttp.Response {
	userID := helpers.AuthUserID(ctx)
	views, err := c.sessions.List(ctx.Request().Origin().Context(), userID, c.currentSessionID(ctx))
	if err != nil {
		return c.internal(ctx)
	}
	return ctx.Response().Json(http.StatusOK, responses.NewSessionListResponse(views))
}

// Destroy godoc
//
//	@ID				terminateSession
//	@Summary		Terminate a session
//	@Description	Signs out one of the current user's other sessions by id. The current session cannot be terminated here (use logout).
//	@Tags			Sessions
//	@Security		CookieAuth
//	@Produce		json
//	@Param			id	path		string	true	"Session ID (UUID)"
//	@Success		200	{object}	responses.MessageResponse
//	@Failure		400	{object}	responses.ErrorResponse
//	@Failure		404	{object}	responses.ErrorResponse
//	@Router			/auth/sessions/{id} [delete]
func (c *SessionsController) Destroy(ctx contractshttp.Context) contractshttp.Response {
	id, errResp := helpers.ParseUUIDParam(ctx, "id")
	if errResp != nil {
		return *errResp
	}
	userID := helpers.AuthUserID(ctx)
	err := c.sessions.Terminate(ctx.Request().Origin().Context(), userID, id, c.currentSessionID(ctx))
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

// DestroyOthers godoc
//
//	@ID				terminateOtherSessions
//	@Summary		Sign out other sessions
//	@Description	Terminates every session for the current user except the current one.
//	@Tags			Sessions
//	@Security		CookieAuth
//	@Produce		json
//	@Success		200	{object}	responses.MessageResponse
//	@Failure		401	{object}	responses.ErrorResponse
//	@Router			/auth/sessions [delete]
func (c *SessionsController) DestroyOthers(ctx contractshttp.Context) contractshttp.Response {
	userID := helpers.AuthUserID(ctx)
	if err := c.sessions.TerminateOthers(ctx.Request().Origin().Context(), userID, c.currentSessionID(ctx)); err != nil {
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
