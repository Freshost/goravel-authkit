// Package controllers holds the goravel-authkit HTTP controllers: the auth
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

	"github.com/freshost/goravel-authkit/helpers"
	"github.com/freshost/goravel-authkit/http/middleware"
	"github.com/freshost/goravel-authkit/http/responses"
	"github.com/freshost/goravel-authkit/models"
	"github.com/freshost/goravel-authkit/services"
)

// The pending-2FA user id and the remember-me intent are stashed in the session
// between the password step and the 2FA challenge under
// helpers.TwoFactorUserIDKey(guard) / helpers.RememberIntentKey(guard) — both
// namespaced per guard so two instances can share one session cookie. The session
// is NOT authenticated until the challenge succeeds.

// AuthController handles the auth endpoints.
type AuthController struct {
	auth               *services.Auth
	audit              *services.Audit     // nil when audit logging is disabled
	twoFactor          *services.TwoFactor // nil when 2FA is disabled
	remember           *services.Remember  // nil when remember-me is disabled
	sessions           *services.Sessions  // nil when session tracking is disabled
	guard              string
	rememberCookieName string
}

// NewAuthController builds the auth controller. Pass a nil audit to disable audit
// writes, a nil twoFactor to disable the two-factor login gate, a nil remember to
// disable persistent "remember me" logins, and a nil sessions to disable
// active-session tracking. rememberCookieName is the per-instance remember cookie
// name (empty → the package default).
func NewAuthController(auth *services.Auth, audit *services.Audit, twoFactor *services.TwoFactor, remember *services.Remember, sessions *services.Sessions, guard, rememberCookieName string) *AuthController {
	return &AuthController{auth: auth, audit: audit, twoFactor: twoFactor, remember: remember, sessions: sessions, guard: guard, rememberCookieName: rememberCookieName}
}

// Login verifies credentials and establishes an httpOnly session cookie, handling
// POST {prefix}/auth/login. It stamps password_changed_at into the session so a
// later password change invalidates other sessions, and is rate-limited. When the
// user has 2FA enabled it returns {two_factor:true} and defers the session until
// the challenge succeeds.
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

	if user.IsDisabled() {
		c.writeAuditAttempt(ctx, req.Email, "auth.login_disabled")
		return ctx.Response().Json(http.StatusForbidden, responses.ErrorResponse{
			Error: "account_disabled", Message: "This account has been disabled",
		})
	}

	// Two-step login: if the user has confirmed 2FA, do NOT establish the
	// session yet. Regenerate the session id (anti-fixation) before stashing the
	// pending user id; the session stays unauthenticated until the challenge.
	if c.twoFactor != nil && user.TwoFactorEnabled() {
		if err := helpers.RegenerateAndPersistSession(ctx); err != nil {
			facades.Log().Errorf("auth: regenerate session: %v", err)
		}
		if sess := ctx.Request().Session(); sess != nil {
			sess.Put(helpers.TwoFactorUserIDKey(c.guard), user.ID.String())
			if req.Remember {
				sess.Put(helpers.RememberIntentKey(c.guard), "1")
			}
		}
		return ctx.Response().Json(http.StatusOK, responses.TwoFactorRequiredResponse{TwoFactor: true})
	}

	return completeLogin(ctx, c.guard, c.rememberCookieName, c.audit, c.remember, c.sessions, req.Remember, user)
}

// completeLogin establishes the authenticated session for a verified user
// (guard login, session-id regeneration, password stamp, audit) and returns the
// user response. Shared by password-only login and the 2FA challenge. When
// remember is non-nil and wantRemember is true it also issues a persistent
// "remember me" cookie.
func completeLogin(ctx contractshttp.Context, guard, rememberCookieName string, audit *services.Audit, remember *services.Remember, sessions *services.Sessions, wantRemember bool, user *models.User) contractshttp.Response {
	if _, err := facades.Auth(ctx).Guard(guard).Login(user); err != nil {
		facades.Log().Errorf("auth: establish session: %v", err)
		return ctx.Response().Json(http.StatusInternalServerError, responses.ErrorResponse{
			Error: "internal_error", Message: "Internal server error",
		})
	}
	if err := helpers.RegenerateAndPersistSession(ctx); err != nil {
		facades.Log().Errorf("auth: regenerate session: %v", err)
	}
	if sess := ctx.Request().Session(); sess != nil {
		sess.Put(helpers.PasswordChangedAtKey(guard), middleware.FormatPasswordTimestamp(user.PasswordChangedAt))
		sess.Forget(helpers.TwoFactorUserIDKey(guard))
		sess.Forget(helpers.RememberIntentKey(guard))
	}
	if remember != nil && wantRemember {
		if value, err := remember.Issue(ctx.Request().Origin().Context(), user.ID); err != nil {
			facades.Log().Errorf("auth: issue remember token: %v", err)
		} else {
			helpers.SetRememberCookie(ctx, rememberCookieName, value, remember.TTL())
		}
	}
	if sessions != nil {
		if sess := ctx.Request().Session(); sess != nil {
			// Active-session tracking is keyed by a stable per-guard token, not the
			// Goravel session id (which rotates on every login, including another
			// guard's login on this shared cookie). Drop any prior token's row
			// (re-login) and issue a fresh one into the session.
			if old := helpers.SessionTrackingToken(ctx, guard); old != "" {
				_ = sessions.Forget(ctx.Request().Origin().Context(), old)
			}
			token := helpers.NewSessionToken()
			sess.Put(helpers.SessionTrackingTokenKey(guard), token)
			if err := sessions.Track(ctx.Request().Origin().Context(), token, user.ID, ctx.Request().Ip(), ctx.Request().Header("User-Agent", "")); err != nil {
				facades.Log().Errorf("auth: track session: %v", err)
			}
		}
	}
	if audit != nil {
		id := user.ID
		rid := id.String()
		if err := audit.Log(ctx.Request().Origin().Context(), services.AuditEntry{
			ActorID: &id, ActorEmail: user.Email, Action: "auth.login", ResourceType: "user", ResourceID: &rid, IP: ctx.Request().Ip(),
		}); err != nil {
			facades.Log().Errorf("audit auth.login: %v", err)
		}
	}
	return ctx.Response().Json(http.StatusOK, responses.NewUserResponse(user))
}

// Logout invalidates the current session and clears the session cookie. Handles
// POST {prefix}/auth/logout.
func (c *AuthController) Logout(ctx contractshttp.Context) contractshttp.Response {
	// Best-effort load of the current user (for the audit row) from the instance's
	// table; the id was injected by Authenticated.
	user, _ := c.auth.Me(ctx.Request().Origin().Context(), helpers.AuthUserID(ctx))

	// Capture this session's tracking token before logout, to drop its row.
	trackingToken := helpers.SessionTrackingToken(ctx, c.guard)

	if err := facades.Auth(ctx).Guard(c.guard).Logout(); err != nil {
		facades.Log().Errorf("auth: logout: %v", err)
	}
	if sess := ctx.Request().Session(); sess != nil {
		sess.Forget(helpers.PasswordChangedAtKey(c.guard))
		sess.Forget(helpers.SessionTrackingTokenKey(c.guard))
	}
	if c.sessions != nil {
		if err := c.sessions.Forget(ctx.Request().Origin().Context(), trackingToken); err != nil {
			facades.Log().Errorf("auth: forget session: %v", err)
		}
	}

	// Drop the persistent remember token (this device) so it can't re-login.
	if c.remember != nil {
		if cookie := helpers.ReadRememberCookie(ctx, c.rememberCookieName); cookie != "" {
			if err := c.remember.Revoke(ctx.Request().Origin().Context(), cookie); err != nil {
				facades.Log().Errorf("auth: revoke remember token: %v", err)
			}
		}
		helpers.ClearRememberCookie(ctx, c.rememberCookieName)
	}

	c.writeAudit(ctx, user, "auth.logout")
	return ctx.Response().Json(http.StatusOK, responses.MessageResponse{Message: "logged out"})
}

// Me returns the currently authenticated user. Handles GET {prefix}/auth/me.
func (c *AuthController) Me(ctx contractshttp.Context) contractshttp.Response {
	user, err := c.auth.Me(ctx.Request().Origin().Context(), helpers.AuthUserID(ctx))
	if err != nil {
		return ctx.Response().Json(http.StatusUnauthorized, responses.ErrorResponse{
			Error: "unauthorized", Message: "Authentication required",
		})
	}
	return ctx.Response().Json(http.StatusOK, responses.NewUserResponse(user))
}

// UpdateProfile updates the authenticated user's own name and email, handling
// PUT {prefix}/auth/me. The role is not changeable here (it is admin-managed) and
// a duplicate email is rejected with a conflict.
func (c *AuthController) UpdateProfile(ctx contractshttp.Context) contractshttp.Response {
	var req responses.UpdateProfileRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return c.badRequest(ctx)
	}

	userID := helpers.AuthUserID(ctx)
	if userID == uuid.Nil {
		return ctx.Response().Json(http.StatusUnauthorized, responses.ErrorResponse{
			Error: "unauthorized", Message: "Authentication required",
		})
	}

	user, changed, err := c.auth.UpdateProfile(ctx.Request().Origin().Context(), userID, req.Email, req.Name)
	if err != nil {
		return c.mapServiceError(ctx, err)
	}

	if changed {
		c.writeAudit(ctx, user, "auth.profile_updated")
	}
	return ctx.Response().Json(http.StatusOK, responses.NewUserResponse(user))
}

// LoginHistory returns the current user's most recent successful sign-ins
// (password or remember cookie) with the IP they came from. Handles
// GET {prefix}/auth/logins.
func (c *AuthController) LoginHistory(ctx contractshttp.Context) contractshttp.Response {
	if c.audit == nil {
		return ctx.Response().Json(http.StatusOK, []responses.LoginHistoryEntry{})
	}
	userID := helpers.AuthUserID(ctx)
	if userID == uuid.Nil {
		return ctx.Response().Json(http.StatusUnauthorized, responses.ErrorResponse{
			Error: "unauthorized", Message: "Authentication required",
		})
	}
	entries, err := c.audit.RecentLogins(ctx.Request().Origin().Context(), userID, 20)
	if err != nil {
		return c.internal(ctx)
	}
	return ctx.Response().Json(http.StatusOK, responses.NewLoginHistoryResponse(entries))
}

// ChangePassword verifies the current password, validates the new one, updates the
// hash, and bumps password_changed_at so every OTHER session is logged out on its
// next request while this session stays valid. Handles PUT {prefix}/auth/password.
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
		sess.Put(helpers.PasswordChangedAtKey(c.guard), middleware.FormatPasswordTimestamp(changedAt))
	}

	// A password change invalidates every other session; revoke all persistent
	// remember tokens too (including this device's) so a leaked cookie can't
	// outlive the password. This session itself stays valid via the re-stamp.
	if c.remember != nil {
		if err := c.remember.RevokeAllForUser(ctx.Request().Origin().Context(), userID); err != nil {
			facades.Log().Errorf("auth: revoke remember tokens: %v", err)
		}
		helpers.ClearRememberCookie(ctx, c.rememberCookieName)
	}
	// Drop the tracking rows for every other session (this one stays).
	if c.sessions != nil {
		currentToken := helpers.SessionTrackingToken(ctx, c.guard)
		if err := c.sessions.TerminateOthers(ctx.Request().Origin().Context(), userID, currentToken); err != nil {
			facades.Log().Errorf("auth: terminate other sessions: %v", err)
		}
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
	case errors.Is(err, services.ErrAlreadyExists):
		return ctx.Response().Json(http.StatusConflict, responses.ErrorResponse{
			Error: "already_exists", Message: "Email already exists",
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

// errMessage returns the joined validation error's full text (sentinel + detail).
func errMessage(err error) string {
	if msg := err.Error(); msg != "" {
		return msg
	}
	return "Validation error"
}
