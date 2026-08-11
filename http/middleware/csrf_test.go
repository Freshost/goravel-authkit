package middleware

import "testing"

import "github.com/stretchr/testify/assert"

func TestVerifyRequestOriginAllowed(t *testing.T) {
	middleware := VerifyRequestOrigin([]string{"https://spa.example.net"}).(*verifyRequestOriginMiddleware)

	assert.True(t, middleware.allowed("app.example.com", "https://app.example.com", "", "cross-site"))
	assert.True(t, middleware.allowed("app.example.com", "https://spa.example.net", "", "cross-site"))
	assert.True(t, middleware.allowed("app.example.com", "", "https://app.example.com/settings", ""))
	assert.True(t, middleware.allowed("app.example.com", "", "", "same-origin"))
}

func TestVerifyRequestOriginRejectsUntrustedOrMissingOrigin(t *testing.T) {
	middleware := VerifyRequestOrigin([]string{"https://spa.example.net"}).(*verifyRequestOriginMiddleware)

	assert.False(t, middleware.allowed("app.example.com", "https://evil.example.net", "", "cross-site"))
	assert.False(t, middleware.allowed("app.example.com", "https://sibling.example.com", "", "same-site"))
	assert.False(t, middleware.allowed("app.example.com", "null", "", "cross-site"))
	assert.False(t, middleware.allowed("app.example.com", "", "", ""))
	assert.False(t, middleware.allowed("app.example.com", "", "", "same-site"))
}

func TestVerifyRequestOriginRejectsMalformedTrustedOrigins(t *testing.T) {
	middleware := VerifyRequestOrigin([]string{"https://spa.example.net/path", "javascript://spa.example.net"}).(*verifyRequestOriginMiddleware)

	assert.Empty(t, middleware.trustedOrigins)
}
