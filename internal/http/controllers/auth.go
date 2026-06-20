// Package controllers holds the goravel-auth HTTP controllers: the auth
// endpoints (login/logout/me/change-password) and the admin user-management
// CRUD. They map service sentinel errors to the {"error","message"} envelope
// using net/http status constants.
package controllers

import (
	"errors"
	"net/http"

	"github.com/google/uuid"
	contractshttp "github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"github.com/freshost/goravel-auth/internal/helpers"
	"github.com/freshost/goravel-auth/internal/http/middleware"
	"github.com/freshost/goravel-auth/internal/http/responses"
	"github.com/freshost/goravel-auth/internal/models"
	"github.com/freshost/goravel-auth/internal/services"
)

// AuthController handles the auth endpoints.
type AuthController struct {
	auth  *services.Auth
	audit *services.Audit // nil when audit logging is disabled
	guard string
}

// NewAuthController builds the auth controller. Pass a nil audit to disable
// audit writes.
func NewAuthController(auth *services.Auth, audit *services.Audit, guard string) *AuthController {
	return &AuthController{auth: auth, audit: audit, guard: guard}
}

// Login godoc
//
//	@ID				login
//	@Summary		Login
//	@Description	Verifies credentials and establishes an httpOnly session cookie. Stamps password_changed_at into the session so a later password change invalidates other sessions. Rate-limited.
//	@Tags			Auth
//	@Accept			json
//	@Produce		json
//	@Param			body	body		responses.LoginRequest	true	"Login credentials"
//	@Success		200		{object}	responses.UserResponse
//	@Failure		400		{object}	responses.ErrorResponse
//	@Failure		401		{object}	responses.ErrorResponse
//	@Failure		429		{object}	responses.ErrorResponse
//	@Failure		500		{object}	responses.ErrorResponse
//	@Router			/auth/login [post]
func (c *AuthController) Login(ctx contractshttp.Context) contractshttp.Response {
	var req responses.LoginRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return c.badRequest(ctx)
	}

	user, err := c.auth.Authenticate(ctx.Request().Origin().Context(), req.Email, req.Password)
	if err != nil {
		c.writeAuditAttempt(ctx, req.Email, "auth.login_failed")
		return c.mapServiceError(ctx, err)
	}

	if _, err := facades.Auth(ctx).Guard(c.guard).Login(user); err != nil {
		facades.Log().Errorf("auth: establish session: %v", err)
		return c.internal(ctx)
	}
	if err := helpers.RegenerateAndPersistSession(ctx); err != nil {
		facades.Log().Errorf("auth: regenerate session: %v", err)
	}
	ctx.Request().Session().Put(
		middleware.SessionKeyPasswordChangedAt,
		middleware.FormatPasswordTimestamp(user.PasswordChangedAt),
	)

	c.writeAudit(ctx, user, "auth.login")
	return ctx.Response().Json(http.StatusOK, responses.NewUserResponse(user))
}

// Logout godoc
//
//	@ID				logout
//	@Summary		Logout
//	@Description	Invalidates the current session and clears the session cookie.
//	@Tags			Auth
//	@Security		CookieAuth
//	@Produce		json
//	@Success		200	{object}	responses.MessageResponse
//	@Failure		401	{object}	responses.ErrorResponse
//	@Router			/auth/logout [post]
func (c *AuthController) Logout(ctx contractshttp.Context) contractshttp.Response {
	var user models.User
	_ = facades.Auth(ctx).Guard(c.guard).User(&user)

	if err := facades.Auth(ctx).Guard(c.guard).Logout(); err != nil {
		facades.Log().Errorf("auth: logout: %v", err)
	}
	if sess := ctx.Request().Session(); sess != nil {
		sess.Forget(middleware.SessionKeyPasswordChangedAt)
	}

	c.writeAudit(ctx, &user, "auth.logout")
	return ctx.Response().Json(http.StatusOK, responses.MessageResponse{Message: "logged out"})
}

// Me godoc
//
//	@ID				getMe
//	@Summary		Get current user
//	@Description	Returns the currently authenticated user.
//	@Tags			Auth
//	@Security		CookieAuth
//	@Produce		json
//	@Success		200	{object}	responses.UserResponse
//	@Failure		401	{object}	responses.ErrorResponse
//	@Router			/auth/me [get]
func (c *AuthController) Me(ctx contractshttp.Context) contractshttp.Response {
	var user models.User
	if err := facades.Auth(ctx).Guard(c.guard).User(&user); err != nil || user.ID == uuid.Nil {
		return ctx.Response().Json(http.StatusUnauthorized, responses.ErrorResponse{
			Error: "unauthorized", Message: "Authentication required",
		})
	}
	return ctx.Response().Json(http.StatusOK, responses.NewUserResponse(&user))
}

// ChangePassword godoc
//
//	@ID				changePassword
//	@Summary		Change own password
//	@Description	Verifies the current password, validates the new one, updates the hash and bumps password_changed_at so every OTHER session is logged out on its next request. This session stays valid.
//	@Tags			Auth
//	@Accept			json
//	@Produce		json
//	@Security		CookieAuth
//	@Param			body	body		responses.ChangePasswordRequest	true	"Current + new password"
//	@Success		200		{object}	responses.MessageResponse
//	@Failure		400		{object}	responses.ErrorResponse
//	@Failure		401		{object}	responses.ErrorResponse
//	@Failure		500		{object}	responses.ErrorResponse
//	@Router			/auth/password [put]
func (c *AuthController) ChangePassword(ctx contractshttp.Context) contractshttp.Response {
	var req responses.ChangePasswordRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return c.badRequest(ctx)
	}

	userID := helpers.AuthUserID(ctx)
	if userID == uuid.Nil {
		return ctx.Response().Json(http.StatusUnauthorized, responses.ErrorResponse{
			Error: "unauthorized", Message: "Authentication required",
		})
	}

	changedAt, err := c.auth.ChangePassword(ctx.Request().Origin().Context(), userID, req.CurrentPassword, req.NewPassword)
	if err != nil {
		return c.mapServiceError(ctx, err)
	}

	// Re-stamp THIS session so it survives the invalidation that just killed
	// every other session.
	if sess := ctx.Request().Session(); sess != nil {
		sess.Put(middleware.SessionKeyPasswordChangedAt, middleware.FormatPasswordTimestamp(changedAt))
	}

	c.writeAuditID(ctx, &userID, "auth.password_changed", userID.String())
	return ctx.Response().Json(http.StatusOK, responses.MessageResponse{Message: "Password changed"})
}

func (c *AuthController) mapServiceError(ctx contractshttp.Context, err error) contractshttp.Response {
	switch {
	case errors.Is(err, services.ErrInvalidCredentials):
		return ctx.Response().Json(http.StatusUnauthorized, responses.ErrorResponse{
			Error: "invalid_credentials", Message: "Invalid email or password",
		})
	case errors.Is(err, services.ErrWrongPassword):
		return ctx.Response().Json(http.StatusBadRequest, responses.ErrorResponse{
			Error: "wrong_password", Message: "Current password is incorrect",
		})
	case errors.Is(err, services.ErrValidation):
		return ctx.Response().Json(http.StatusBadRequest, responses.ErrorResponse{
			Error: "validation_error", Message: errMessage(err),
		})
	case errors.Is(err, services.ErrUnauthorized):
		return ctx.Response().Json(http.StatusUnauthorized, responses.ErrorResponse{
			Error: "unauthorized", Message: "Authentication required",
		})
	default:
		facades.Log().Errorf("auth internal error: %v", err)
		return c.internal(ctx)
	}
}

func (c *AuthController) badRequest(ctx contractshttp.Context) contractshttp.Response {
	return ctx.Response().Json(http.StatusBadRequest, responses.ErrorResponse{
		Error: "validation_error", Message: "Invalid request body",
	})
}

func (c *AuthController) internal(ctx contractshttp.Context) contractshttp.Response {
	return ctx.Response().Json(http.StatusInternalServerError, responses.ErrorResponse{
		Error: "internal_error", Message: "Internal server error",
	})
}

// writeAudit records an action performed by/affecting the given user.
func (c *AuthController) writeAudit(ctx contractshttp.Context, user *models.User, action string) {
	if user == nil || user.ID == uuid.Nil {
		return
	}
	id := user.ID
	c.writeAuditID(ctx, &id, action, id.String())
}

// writeAuditAttempt records a failed login (no actor; the attempted email goes
// into metadata) so brute-force activity leaves a forensic trail.
func (c *AuthController) writeAuditAttempt(ctx contractshttp.Context, email, action string) {
	if c.audit == nil {
		return
	}
	if err := c.audit.Log(ctx.Request().Origin().Context(), services.AuditEntry{
		Action:       action,
		ResourceType: "user",
		Metadata:     map[string]any{"email": email},
		IP:           ctx.Request().Ip(),
	}); err != nil {
		facades.Log().Errorf("audit %s: %v", action, err)
	}
}

func (c *AuthController) writeAuditID(ctx contractshttp.Context, actorID *uuid.UUID, action, resourceID string) {
	if c.audit == nil {
		return
	}
	rid := resourceID
	if err := c.audit.Log(ctx.Request().Origin().Context(), services.AuditEntry{
		ActorID:      actorID,
		Action:       action,
		ResourceType: "user",
		ResourceID:   &rid,
		IP:           ctx.Request().Ip(),
	}); err != nil {
		facades.Log().Errorf("audit %s: %v", action, err)
	}
}

// errMessage returns the human-readable tail of a joined validation error.
func errMessage(err error) string {
	if msg := err.Error(); msg != "" {
		return msg
	}
	return "Validation error"
}
