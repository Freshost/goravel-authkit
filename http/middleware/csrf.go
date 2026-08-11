package middleware

import (
	"net/http"
	"net/url"
	"strings"

	contractshttp "github.com/goravel/framework/contracts/http"
)

// VerifyRequestOrigin rejects state-changing browser requests that do not come
// from the request host or an explicitly trusted origin. Missing origin signals
// fail closed; non-browser clients must send Origin as well.
func VerifyRequestOrigin(trustedOrigins []string) contractshttp.Middleware {
	trusted := make(map[string]struct{}, len(trustedOrigins))
	for _, origin := range trustedOrigins {
		if normalized, ok := normalizeTrustedOrigin(origin); ok {
			trusted[normalized] = struct{}{}
		}
	}
	return &verifyRequestOriginMiddleware{trustedOrigins: trusted}
}

type verifyRequestOriginMiddleware struct {
	trustedOrigins map[string]struct{}
}

func (middleware *verifyRequestOriginMiddleware) Handle(ctx contractshttp.Context) {
	request := ctx.Request()
	if isSafeMethod(request.Method()) || middleware.allowed(request.Host(), request.Header("Origin"), request.Header("Referer"), request.Header("Sec-Fetch-Site")) {
		request.Next()
		return
	}

	_ = ctx.Response().Json(http.StatusForbidden, contractshttp.Json{
		"error": "csrf_failed", "message": "Request origin could not be verified.",
	}).Abort()
}

func (middleware *verifyRequestOriginMiddleware) Signature() string {
	return "goravel-authkit.verify-request-origin"
}

func (middleware *verifyRequestOriginMiddleware) allowed(host, origin, referer, fetchSite string) bool {
	if origin != "" {
		return middleware.allowedURL(host, origin, false)
	}
	if referer != "" {
		return middleware.allowedURL(host, referer, true)
	}
	return strings.EqualFold(strings.TrimSpace(fetchSite), "same-origin")
}

func (middleware *verifyRequestOriginMiddleware) allowedURL(host, raw string, allowPath bool) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil {
		return false
	}
	if !allowPath && (parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "") {
		return false
	}
	if !strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https") {
		return false
	}
	if equalHost(parsed.Host, host) {
		return true
	}
	_, ok := middleware.trustedOrigins[canonicalOrigin(parsed)]
	return ok
}

func normalizeTrustedOrigin(raw string) (string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", false
	}
	if !strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https") {
		return "", false
	}
	return canonicalOrigin(parsed), true
}

func canonicalOrigin(parsed *url.URL) string {
	return strings.ToLower(parsed.Scheme) + "://" + strings.ToLower(strings.TrimSuffix(parsed.Host, "."))
}

func equalHost(left, right string) bool {
	return strings.EqualFold(strings.TrimSuffix(left, "."), strings.TrimSuffix(right, "."))
}

func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}
