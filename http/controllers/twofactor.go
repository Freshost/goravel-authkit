package controllers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	contractshttp "github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"github.com/freshost/goravel-authkit/helpers"
	"github.com/freshost/goravel-authkit/http/middleware"
	"github.com/freshost/goravel-authkit/http/responses"
	"github.com/freshost/goravel-authkit/services"
)

// TwoFactorController handles TOTP two-factor: the login challenge (completing a
// pending login) and the management endpoints (enable/confirm/disable/recovery).
type TwoFactorController struct {
	users              *services.Users
	auth               *services.Auth
	twoFactor          *services.TwoFactor
	audit              *services.Audit
	remember           *services.Remember // nil when remember-me is disabled
	sessions           *services.Sessions // nil when session tracking is disabled
	guard              string
	rememberCookieName string
	rateLimiter        *middleware.AttemptLimiter
	accountAttempts    int
}

// NewTwoFactorController builds the two-factor controller. Pass a nil remember to
// disable persistent "remember me" logins, and a nil sessions to disable
// active-session tracking. rememberCookieName is the per-instance remember cookie
// name (empty → the package default).
func NewTwoFactorController(users *services.Users, auth *services.Auth, twoFactor *services.TwoFactor, audit *services.Audit, remember *services.Remember, sessions *services.Sessions, guard, rememberCookieName string, rateLimiter *middleware.AttemptLimiter, accountAttempts int) *TwoFactorController {
	return &TwoFactorController{users: users, auth: auth, twoFactor: twoFactor, audit: audit, remember: remember, sessions: sessions, guard: guard, rememberCookieName: rememberCookieName, rateLimiter: rateLimiter, accountAttempts: accountAttempts}
}

// Challenge completes a login that returned {two_factor:true} by verifying a TOTP
// code or a single-use recovery code against the pending user, establishing the
// session on success. It is rate-limited and handles
// POST {prefix}/auth/two-factor-challenge.
func (c *TwoFactorController) Challenge(ctx contractshttp.Context) contractshttp.Response {
	sess := ctx.Request().Session()
	if sess == nil {
		return c.unauthorized(ctx, "no pending two-factor challenge")
	}
	raw, _ := sess.Get(helpers.TwoFactorUserIDKey(c.guard)).(string)
	id, err := uuid.Parse(raw)
	if err != nil || id == uuid.Nil {
		return c.unauthorized(ctx, "no pending two-factor challenge")
	}
	if response := enforceRateLimit(ctx, c.rateLimiter, "two-factor-user", id.String(), c.accountAttempts); response != nil {
		return response
	}

	var req responses.TwoFactorChallengeRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return c.badRequest(ctx, "Invalid request body")
	}

	user, err := c.users.GetByID(ctx.Context(), id)
	if err != nil {
		return c.unauthorized(ctx, "no pending two-factor challenge")
	}

	var ok bool
	switch {
	case strings.TrimSpace(req.Code) != "":
		ok, err = c.twoFactor.VerifyLoginCode(ctx.Context(), id, req.Code)
	case strings.TrimSpace(req.RecoveryCode) != "":
		ok, err = c.twoFactor.ConsumeRecoveryCode(ctx.Context(), id, req.RecoveryCode)
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
	if raw, ok := sess.Get(helpers.RememberIntentKey(c.guard)).(string); ok && raw == "1" {
		wantRemember = true
	}

	return completeLogin(ctx, c.guard, c.rememberCookieName, c.audit, c.remember, c.sessions, wantRemember, user)
}

// Enable starts 2FA enrollment by generating a TOTP secret (not yet active) and
// returning the secret plus otpauth URL for QR rendering; confirm with a code to
// activate. Handles POST {prefix}/auth/two-factor.
func (c *TwoFactorController) Enable(ctx contractshttp.Context) contractshttp.Response {
	id := helpers.AuthUserID(ctx)
	enr, err := c.twoFactor.Enable(ctx.Context(), id)
	if err != nil {
		return c.mapError(ctx, err)
	}
	c.writeAudit(ctx, &id, "auth.two_factor_enrolled")
	return ctx.Response().Json(http.StatusOK, responses.TwoFactorEnrollmentResponse{
		Secret: enr.Secret, OtpauthURL: enr.OtpauthURL,
	})
}

// Confirm verifies a TOTP code against the pending secret, activates 2FA, and
// returns the one-time recovery codes (shown only once). Handles
// POST {prefix}/auth/two-factor/confirm.
func (c *TwoFactorController) Confirm(ctx contractshttp.Context) contractshttp.Response {
	id := helpers.AuthUserID(ctx)
	var req responses.TwoFactorConfirmRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return c.badRequest(ctx, "Invalid request body")
	}
	codes, err := c.twoFactor.Confirm(ctx.Context(), id, req.Code)
	if err != nil {
		return c.mapError(ctx, err)
	}
	c.writeAudit(ctx, &id, "auth.two_factor_confirmed")
	return ctx.Response().Json(http.StatusOK, responses.RecoveryCodesResponse{RecoveryCodes: codes})
}

// Disable clears the user's two-factor secret and recovery codes, handling
// DELETE {prefix}/auth/two-factor. It requires the account password to confirm
// (re-auth), so a stolen session alone cannot silently remove 2FA.
func (c *TwoFactorController) Disable(ctx contractshttp.Context) contractshttp.Response {
	id := helpers.AuthUserID(ctx)

	var req responses.TwoFactorDisableRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return c.badRequest(ctx, "Invalid request body")
	}
	user, err := c.users.GetByID(ctx.Context(), id)
	if err != nil {
		return c.mapError(ctx, err)
	}
	// Re-auth: confirm the account password before removing 2FA.
	if _, err := c.auth.Authenticate(ctx.Context(), user.Email, req.Password); err != nil {
		return c.unauthorized(ctx, "Password confirmation failed")
	}

	if err := c.twoFactor.Disable(ctx.Context(), id); err != nil {
		return c.mapError(ctx, err)
	}
	c.writeAudit(ctx, &id, "auth.two_factor_disabled")
	return ctx.Response().Json(http.StatusOK, responses.MessageResponse{Message: "Two-factor disabled"})
}

// RecoveryCodes returns how many unused recovery codes remain, handling
// GET {prefix}/auth/two-factor/recovery-codes. The codes are stored hashed and
// shown only once (at confirmation or regeneration); this endpoint never returns
// plaintext codes.
func (c *TwoFactorController) RecoveryCodes(ctx contractshttp.Context) contractshttp.Response {
	id := helpers.AuthUserID(ctx)
	remaining, err := c.twoFactor.RemainingRecoveryCodes(ctx.Context(), id)
	if err != nil {
		return c.mapError(ctx, err)
	}
	return ctx.Response().Json(http.StatusOK, responses.RecoveryCodesStatusResponse{Remaining: remaining})
}

// RegenerateRecoveryCodes replaces the recovery codes, invalidating the previous
// set. Handles POST {prefix}/auth/two-factor/recovery-codes.
func (c *TwoFactorController) RegenerateRecoveryCodes(ctx contractshttp.Context) contractshttp.Response {
	id := helpers.AuthUserID(ctx)
	codes, err := c.twoFactor.RegenerateRecoveryCodes(ctx.Context(), id)
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
	if err := c.audit.Log(ctx.Context(), services.AuditEntry{
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
