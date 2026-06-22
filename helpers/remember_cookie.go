package helpers

import (
	"time"

	contractshttp "github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"
)

// RememberCookieName is the cookie carrying the persistent "remember me" token
// (selector:validator). It is separate from the session cookie and long-lived.
const RememberCookieName = "authkit_remember"

// ReadRememberCookie returns the raw remember cookie value, or "" when absent.
func ReadRememberCookie(ctx contractshttp.Context) string {
	return ctx.Request().Cookie(RememberCookieName)
}

// SetRememberCookie writes the remember cookie with the given value and lifetime.
// It mirrors the session cookie's security attributes (secure/domain/same_site)
// so it behaves consistently behind the same proxy/origin, but is always
// http_only (JavaScript must never read it).
func SetRememberCookie(ctx contractshttp.Context, value string, ttl time.Duration) {
	config := facades.Config()
	ctx.Response().Cookie(contractshttp.Cookie{
		Name:     RememberCookieName,
		Value:    value,
		Path:     config.GetString("session.path", "/"),
		Domain:   config.GetString("session.domain"),
		MaxAge:   int(ttl.Seconds()),
		Secure:   config.GetBool("session.secure", false),
		HttpOnly: true,
		SameSite: config.GetString("session.same_site", "lax"),
	})
}

// ClearRememberCookie expires the remember cookie on the client.
func ClearRememberCookie(ctx contractshttp.Context) {
	config := facades.Config()
	ctx.Response().Cookie(contractshttp.Cookie{
		Name:     RememberCookieName,
		Value:    "",
		Path:     config.GetString("session.path", "/"),
		Domain:   config.GetString("session.domain"),
		MaxAge:   -1,
		Secure:   config.GetBool("session.secure", false),
		HttpOnly: true,
		SameSite: config.GetString("session.same_site", "lax"),
	})
}
