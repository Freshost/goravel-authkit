package middleware

import (
	contractshttp "github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"github.com/freshost/goravel-authkit/helpers"
	"github.com/freshost/goravel-authkit/services"
)

// TrackSession enforces the active-session list: it refreshes the current
// session's last-active time and, when the row is gone, treats the session as
// terminated (signs it out). It must run AFTER Authenticated (a live session is
// assumed). Rows are created at login, not here — so a missing row means the
// session was terminated remotely (or predates the feature). A DB error fails
// open so a transient outage doesn't lock everyone out.
func TrackSession(guard string, sessions *services.Sessions) contractshttp.Middleware {
	return &trackSessionMiddleware{guard: guard, sessions: sessions}
}

type trackSessionMiddleware struct {
	guard    string
	sessions *services.Sessions
}

func (middleware *trackSessionMiddleware) Handle(ctx contractshttp.Context) {
	guard := middleware.guard
	sessions := middleware.sessions
	sess := ctx.Request().Session()
	if sess == nil {
		ctx.Request().Next()
		return
	}
	alive, err := sessions.Touch(ctx.Context(), helpers.SessionTrackingToken(ctx, guard))
	if err != nil {
		facades.Log().Errorf("track session: %v", err)
		ctx.Request().Next()
		return
	}
	if !alive {
		_ = facades.Auth(ctx).Guard(guard).Logout()
		_ = ctx.Response().Json(401, contractshttp.Json{
			"error":   "session_terminated",
			"message": "This session has been signed out",
		}).Abort()
		return
	}
	ctx.Request().Next()
}

func (middleware *trackSessionMiddleware) Signature() string {
	return "goravel-authkit.track-session." + middleware.guard
}
