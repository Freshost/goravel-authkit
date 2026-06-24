package helpers

import (
	"time"

	contractshttp "github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"
)

// DefaultRememberCookieName is the cookie carrying the persistent "remember me"
// token (selector:validator). It is separate from the session cookie and
// long-lived. Two authkit instances on one origin must use distinct names (via
// Options.RememberCookieName) so their remember cookies don't overwrite each other.
const DefaultRememberCookieName = "authkit_remember"

// rememberCookieName falls back to the package default for an empty name so a
// zero-valued option reproduces single-instance behaviour.
func rememberCookieName(name string) string {
	if name == "" {
		return DefaultRememberCookieName
	}
	return name
}

// ReadRememberCookie returns the raw remember cookie value, or "" when absent.
func ReadRememberCookie(ctx contractshttp.Context, name string) string {
	return ctx.Request().Cookie(rememberCookieName(name))
}

// SetRememberCookie writes the remember cookie with the given value and lifetime.
// It mirrors the session cookie's security attributes (secure/domain/same_site)
// so it behaves consistently behind the same proxy/origin, but is always
// http_only (JavaScript must never read it).
func SetRememberCookie(ctx contractshttp.Context, name, value string, ttl time.Duration) {
	config := facades.Config()
	ctx.Response().Cookie(contractshttp.Cookie{
		Name:     rememberCookieName(name),
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
func ClearRememberCookie(ctx contractshttp.Context, name string) {
	config := facades.Config()
	ctx.Response().Cookie(contractshttp.Cookie{
		Name:     rememberCookieName(name),
		Value:    "",
		Path:     config.GetString("session.path", "/"),
		Domain:   config.GetString("session.domain"),
		MaxAge:   -1,
		Secure:   config.GetBool("session.secure", false),
		HttpOnly: true,
		SameSite: config.GetString("session.same_site", "lax"),
	})
}
