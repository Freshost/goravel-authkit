package controllers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	contractshttp "github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"github.com/freshost/goravel-authkit/helpers"
	"github.com/freshost/goravel-authkit/http/responses"
	"github.com/freshost/goravel-authkit/services"
)

// TwoFactorController handles TOTP two-factor: the login challenge (completing a
// pending login) and the management endpoints (enable/confirm/disable/recovery).
type TwoFactorController struct {
	users     *services.Users
	auth      *services.Auth
	twoFactor *services.TwoFactor
	audit     *services.Audit
	remember  *services.Remember // nil when remember-me is disabled
	sessions  *services.Sessions // nil when session tracking is disabled
	guard     string
}

// NewTwoFactorController builds the two-factor controller. Pass a nil remember to
// disable persistent "remember me" logins, and a nil sessions to disable
// active-session tracking.
func NewTwoFactorController(users *services.Users, auth *services.Auth, twoFactor *services.TwoFactor, audit *services.Audit, remember *services.Remember, sessions *services.Sessions, guard string) *TwoFactorController {
	return &TwoFactorController{users: users, auth: auth, twoFactor: twoFactor, audit: audit, remember: remember, sessions: sessions, guard: guard}
}

// Challenge godoc
//
//	@ID				twoFactorChallenge
//	@Summary		Complete a 2FA login
//	@Description	Completes a login that returned {two_factor:true} by verifying a TOTP code or a single-use recovery code against the pending user. Establishes the session on success. Rate-limited.
//	@Tags			Auth
//	@Accept			json
//	@Produce		json
//	@Param			body	body		responses.TwoFactorChallengeRequest	true	"TOTP or recovery code"
//	@Success		200		{object}	responses.UserResponse
//	@Failure		400		{object}	responses.ErrorResponse
//	@Failure		401		{object}	responses.ErrorResponse
//	@Failure		429		{object}	responses.ErrorResponse
//	@Router			/auth/two-factor-challenge [post]
func (c *TwoFactorController) Challenge(ctx contractshttp.Context) contractshttp.Response {
	sess := ctx.Request().Session()
	if sess == nil {
		return c.unauthorized(ctx, "no pending two-factor challenge")
	}
	raw, _ := sess.Get(SessionKeyTwoFactorUserID).(string)
	id, err := uuid.Parse(raw)
	if err != nil || id == uuid.Nil {
		return c.unauthorized(ctx, "no pending two-factor challenge")
	}

	var req responses.TwoFactorChallengeRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return c.badRequest(ctx, "Invalid request body")
	}

	user, err := c.users.GetByID(ctx.Request().Origin().Context(), id)
	if err != nil {
		return c.unauthorized(ctx, "no pending two-factor challenge")
	}

	var ok bool
	switch {
	case strings.TrimSpace(req.Code) != "":
		ok, err = c.twoFactor.VerifyLoginCode(ctx.Request().Origin().Context(), id, req.Code)
	case strings.TrimSpace(req.RecoveryCode) != "":
		ok, err = c.twoFactor.ConsumeRecoveryCode(ctx.Request().Origin().Context(), id, req.RecoveryCode)
	default:
		return c.badRequest(ctx, "A code or recoveryCode is required")
	}
	if err != nil {
		facades.Log().Errorf("2fa challenge: %v", err)
		return c.mapError(ctx, err)
	}
	if !ok {
		c.writeAudit(ctx, &id, "auth.two_factor_failed")
		return ctx.Response().Json(http.StatusUnauthorized, responses.ErrorResponse{
			Error: "invalid_code", Message: "Invalid two-factor code",
		})
	}

	// Honour the remember-me intent stashed during the password step.
	wantRemember := false
	if raw, ok := sess.Get(SessionKeyRememberIntent).(string); ok && raw == "1" {
		wantRemember = true
	}

	return completeLogin(ctx, c.guard, c.audit, c.remember, c.sessions, wantRemember, user)
}

// Enable godoc
//
//	@ID				enableTwoFactor
//	@Summary		Start 2FA enrollment
//	@Description	Generates a TOTP secret (not yet active) and returns the secret + otpauth URL for QR rendering. Confirm with a code to activate.
//	@Tags			Auth
//	@Produce		json
//	@Security		CookieAuth
//	@Success		200	{object}	responses.TwoFactorEnrollmentResponse
//	@Failure		401	{object}	responses.ErrorResponse
//	@Failure		409	{object}	responses.ErrorResponse
//	@Router			/auth/two-factor [post]
func (c *TwoFactorController) Enable(ctx contractshttp.Context) contractshttp.Response {
	id := helpers.AuthUserID(ctx)
	enr, err := c.twoFactor.Enable(ctx.Request().Origin().Context(), id)
	if err != nil {
		return c.mapError(ctx, err)
	}
	c.writeAudit(ctx, &id, "auth.two_factor_enrolled")
	return ctx.Response().Json(http.StatusOK, responses.TwoFactorEnrollmentResponse{
		Secret: enr.Secret, OtpauthURL: enr.OtpauthURL,
	})
}

// Confirm godoc
//
//	@ID				confirmTwoFactor
//	@Summary		Confirm 2FA enrollment
//	@Description	Verifies a TOTP code against the pending secret, activates 2FA, and returns one-time recovery codes (shown once).
//	@Tags			Auth
//	@Accept			json
//	@Produce		json
//	@Security		CookieAuth
//	@Param			body	body		responses.TwoFactorConfirmRequest	true	"TOTP code"
//	@Success		200		{object}	responses.RecoveryCodesResponse
//	@Failure		400		{object}	responses.ErrorResponse
//	@Failure		401		{object}	responses.ErrorResponse
//	@Router			/auth/two-factor/confirm [post]
func (c *TwoFactorController) Confirm(ctx contractshttp.Context) contractshttp.Response {
	id := helpers.AuthUserID(ctx)
	var req responses.TwoFactorConfirmRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return c.badRequest(ctx, "Invalid request body")
	}
	codes, err := c.twoFactor.Confirm(ctx.Request().Origin().Context(), id, req.Code)
	if err != nil {
		return c.mapError(ctx, err)
	}
	c.writeAudit(ctx, &id, "auth.two_factor_confirmed")
	return ctx.Response().Json(http.StatusOK, responses.RecoveryCodesResponse{RecoveryCodes: codes})
}

// Disable godoc
//
//	@ID				disableTwoFactor
//	@Summary		Disable 2FA
//	@Description	Clears the user's two-factor secret and recovery codes. Requires the account password to confirm (re-auth), so a stolen session alone cannot silently remove 2FA.
//	@Tags			Auth
//	@Accept			json
//	@Produce		json
//	@Security		CookieAuth
//	@Param			body	body		responses.TwoFactorDisableRequest	true	"Account password"
//	@Success		200		{object}	responses.MessageResponse
//	@Failure		401		{object}	responses.ErrorResponse
//	@Router			/auth/two-factor [delete]
func (c *TwoFactorController) Disable(ctx contractshttp.Context) contractshttp.Response {
	id := helpers.AuthUserID(ctx)

	var req responses.TwoFactorDisableRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return c.badRequest(ctx, "Invalid request body")
	}
	user, err := c.users.GetByID(ctx.Request().Origin().Context(), id)
	if err != nil {
		return c.mapError(ctx, err)
	}
	// Re-auth: confirm the account password before removing 2FA.
	if _, err := c.auth.Authenticate(ctx.Request().Origin().Context(), user.Email, req.Password); err != nil {
		return c.unauthorized(ctx, "Password confirmation failed")
	}

	if err := c.twoFactor.Disable(ctx.Request().Origin().Context(), id); err != nil {
		return c.mapError(ctx, err)
	}
	c.writeAudit(ctx, &id, "auth.two_factor_disabled")
	return ctx.Response().Json(http.StatusOK, responses.MessageResponse{Message: "Two-factor disabled"})
}

// RecoveryCodes godoc
//
//	@ID				getTwoFactorRecoveryCodes
//	@Summary		List remaining recovery codes
//	@Tags			Auth
//	@Produce		json
//	@Security		CookieAuth
//	@Success		200	{object}	responses.RecoveryCodesResponse
//	@Failure		401	{object}	responses.ErrorResponse
//	@Router			/auth/two-factor/recovery-codes [get]
func (c *TwoFactorController) RecoveryCodes(ctx contractshttp.Context) contractshttp.Response {
	id := helpers.AuthUserID(ctx)
	codes, err := c.twoFactor.RecoveryCodes(ctx.Request().Origin().Context(), id)
	if err != nil {
		return c.mapError(ctx, err)
	}
	return ctx.Response().Json(http.StatusOK, responses.RecoveryCodesResponse{RecoveryCodes: codes})
}

// RegenerateRecoveryCodes godoc
//
//	@ID				regenerateTwoFactorRecoveryCodes
//	@Summary		Regenerate recovery codes
//	@Description	Replaces the recovery codes, invalidating the previous set.
//	@Tags			Auth
//	@Produce		json
//	@Security		CookieAuth
//	@Success		200	{object}	responses.RecoveryCodesResponse
//	@Failure		401	{object}	responses.ErrorResponse
//	@Router			/auth/two-factor/recovery-codes [post]
func (c *TwoFactorController) RegenerateRecoveryCodes(ctx contractshttp.Context) contractshttp.Response {
	id := helpers.AuthUserID(ctx)
	codes, err := c.twoFactor.RegenerateRecoveryCodes(ctx.Request().Origin().Context(), id)
	if err != nil {
		return c.mapError(ctx, err)
	}
	c.writeAudit(ctx, &id, "auth.two_factor_recovery_regenerated")
	return ctx.Response().Json(http.StatusOK, responses.RecoveryCodesResponse{RecoveryCodes: codes})
}

func (c *TwoFactorController) writeAudit(ctx contractshttp.Context, actorID *uuid.UUID, action string) {
	if c.audit == nil {
		return
	}
	rid := ""
	if actorID != nil {
		rid = actorID.String()
	}
	if err := c.audit.Log(ctx.Request().Origin().Context(), services.AuditEntry{
		ActorID: actorID, Action: action, ResourceType: "user", ResourceID: &rid, IP: ctx.Request().Ip(),
	}); err != nil {
		facades.Log().Errorf("audit %s: %v", action, err)
	}
}

func (c *TwoFactorController) mapError(ctx contractshttp.Context, err error) contractshttp.Response {
	switch {
	case errors.Is(err, services.ErrInvalidCode):
		return ctx.Response().Json(http.StatusBadRequest, responses.ErrorResponse{
			Error: "invalid_code", Message: "Invalid two-factor code",
		})
	case errors.Is(err, services.ErrTwoFactorAlreadyEnabled):
		return ctx.Response().Json(http.StatusConflict, responses.ErrorResponse{
			Error: "already_enabled", Message: "Two-factor is already enabled",
		})
	case errors.Is(err, services.ErrTwoFactorNotEnrolled):
		return ctx.Response().Json(http.StatusConflict, responses.ErrorResponse{
			Error: "not_enrolled", Message: "Two-factor is not enrolled",
		})
	case errors.Is(err, services.ErrNotFound):
		return ctx.Response().Json(http.StatusNotFound, responses.ErrorResponse{
			Error: "not_found", Message: "User not found",
		})
	default:
		facades.Log().Errorf("two-factor error: %v", err)
		return ctx.Response().Json(http.StatusInternalServerError, responses.ErrorResponse{
			Error: "internal_error", Message: "Internal server error",
		})
	}
}

func (c *TwoFactorController) unauthorized(ctx contractshttp.Context, msg string) contractshttp.Response {
	return ctx.Response().Json(http.StatusUnauthorized, responses.ErrorResponse{Error: "unauthorized", Message: msg})
}

func (c *TwoFactorController) badRequest(ctx contractshttp.Context, msg string) contractshttp.Response {
	return ctx.Response().Json(http.StatusBadRequest, responses.ErrorResponse{Error: "validation_error", Message: msg})
}
