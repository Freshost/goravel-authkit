package middleware

import (
	contractshttp "github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"github.com/freshost/goravel-authkit/helpers"
	"github.com/freshost/goravel-authkit/repositories"
	"github.com/freshost/goravel-authkit/services"
)

// RememberLogin re-establishes a session from a valid "remember me" cookie when
// the request has no live session. It must run BEFORE Authenticated (so the
// freshly-logged-in user is seen) and only matters on guarded routes. When the
// cookie is missing, already-authenticated, or invalid it is a transparent
// no-op (invalid cookies are cleared). On success it logs the user in via the
// native session guard, stamps password_changed_at, rotates the session id,
// re-issues the rotated remember cookie, and audits the silent login. A disabled
// account is refused and its remember tokens revoked. Pass a nil audit to skip
// the audit write.
func RememberLogin(guard, rememberCookieName string, users repositories.UsersRepository, remember *services.Remember, audit *services.Audit, sessions *services.Sessions) contractshttp.Middleware {
	return func(ctx contractshttp.Context) {
		// Already authenticated, or no remember cookie: nothing to do.
		if facades.Auth(ctx).Guard(guard).Check() {
			ctx.Request().Next()
			return
		}
		cookie := helpers.ReadRememberCookie(ctx, rememberCookieName)
		if cookie == "" {
			ctx.Request().Next()
			return
		}

		userID, rotated, err := remember.Resolve(ctx.Request().Origin().Context(), cookie)
		if err != nil {
			helpers.ClearRememberCookie(ctx, rememberCookieName)
			ctx.Request().Next()
			return
		}

		if _, err := facades.Auth(ctx).Guard(guard).LoginUsingID(userID.String()); err != nil {
			facades.Log().Errorf("remember: establish session: %v", err)
			helpers.ClearRememberCookie(ctx, rememberCookieName)
			ctx.Request().Next()
			return
		}

		// Confirm the account still exists and is not locked (loaded from the
		// instance's table, not Goravel's model-bound provider).
		user, err := users.FindByID(ctx.Request().Origin().Context(), userID)
		if err != nil || user == nil || user.IsDisabled() {
			_ = facades.Auth(ctx).Guard(guard).Logout()
			_ = remember.RevokeAllForUser(ctx.Request().Origin().Context(), userID)
			helpers.ClearRememberCookie(ctx, rememberCookieName)
			ctx.Request().Next()
			return
		}

		if sess := ctx.Request().Session(); sess != nil {
			sess.Put(helpers.PasswordChangedAtKey(guard), FormatPasswordTimestamp(user.PasswordChangedAt))
		}
		if err := helpers.RegenerateAndPersistSession(ctx); err != nil {
			facades.Log().Errorf("remember: regenerate session: %v", err)
		}
		// Track the freshly re-established session so it shows in the active list.
		// Keyed by a stable per-guard token (not the rotating session id).
		if sessions != nil {
			if sess := ctx.Request().Session(); sess != nil {
				if old := helpers.SessionTrackingToken(ctx, guard); old != "" {
					_ = sessions.Forget(ctx.Request().Origin().Context(), old)
				}
				token := helpers.NewSessionToken()
				sess.Put(helpers.SessionTrackingTokenKey(guard), token)
				if err := sessions.Track(ctx.Request().Origin().Context(), token, user.ID, ctx.Request().Ip(), ctx.Request().Header("User-Agent", "")); err != nil {
					facades.Log().Errorf("remember: track session: %v", err)
				}
			}
		}
		// Resolve returns an empty value when a concurrent request already rotated
		// the cookie — in that case leave the existing cookie untouched.
		if rotated != "" {
			helpers.SetRememberCookie(ctx, rememberCookieName, rotated, remember.TTL())
		}

		if audit != nil {
			id := user.ID
			rid := id.String()
			if err := audit.Log(ctx.Request().Origin().Context(), services.AuditEntry{
				ActorID: &id, ActorEmail: user.Email, Action: "auth.login_remember", ResourceType: "user", ResourceID: &rid, IP: ctx.Request().Ip(),
			}); err != nil {
				facades.Log().Errorf("audit auth.login_remember: %v", err)
			}
		}

		ctx.Request().Next()
	}
}
