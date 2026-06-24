package middleware

import (
	nethttp "net/http"
	"sync"
	"time"

	contractshttp "github.com/goravel/framework/contracts/http"
)

// rateLimiter is a simple in-memory sliding-window limiter keyed by client IP.
// It is per-process: with multiple app instances the effective limit is
// attempts × instances (a shared-store limiter is out of scope for v1).
//
// SECURITY NOTE: keying is by ctx.Request().Ip(), which honours X-Forwarded-For.
// Behind a proxy, the consuming app MUST configure trusted proxies (Goravel
// http.trusted_proxies) or the limit is bypassable by spoofing the header — the
// same requirement applies to audit-log IPs. See docs/security.md.
type rateLimiter struct {
	mu        sync.Mutex
	requests  map[string][]time.Time
	lastSweep time.Time
}

// RateLimitAuth limits the login endpoint to maxAttempts per window per IP.
// Recommended: 5/min. Pass a large maxAttempts in local/dev env to relax it.
//
// Each call builds its OWN limiter, captured in the returned middleware closure,
// so two authkit instances mounted in one app never share a single IP-keyed
// bucket (a client login failure must not count against the admin limit).
func RateLimitAuth(maxAttempts int, window time.Duration) contractshttp.Middleware {
	limiter := &rateLimiter{requests: make(map[string][]time.Time)}
	return func(ctx contractshttp.Context) {
		ip := ctx.Request().Ip()
		if limiter.isLimited(ip, maxAttempts, window) {
			_ = ctx.Response().Json(nethttp.StatusTooManyRequests, contractshttp.Json{
				"error":   "rate_limited",
				"message": "Too many attempts. Please try again later.",
			}).Abort()
			return
		}
		limiter.record(ip, window)
		ctx.Request().Next()
	}
}

func (rl *rateLimiter) isLimited(key string, maxAttempts int, window time.Duration) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	cutoff := time.Now().Add(-window)
	if times, ok := rl.requests[key]; ok {
		valid := times[:0:0]
		for _, t := range times {
			if t.After(cutoff) {
				valid = append(valid, t)
			}
		}
		rl.requests[key] = valid
		return len(valid) >= maxAttempts
	}
	return false
}

func (rl *rateLimiter) record(key string, window time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	rl.requests[key] = append(rl.requests[key], now)

	// Periodic global sweep evicts IPs with no recent attempts so the map does
	// not grow unboundedly under IP rotation. Runs at most once per window.
	if now.Sub(rl.lastSweep) > window {
		rl.sweepLocked(now.Add(-window))
		rl.lastSweep = now
	}
}

// sweepLocked prunes stale timestamps and deletes empty keys. Caller holds mu.
func (rl *rateLimiter) sweepLocked(cutoff time.Time) {
	for k, times := range rl.requests {
		valid := times[:0:0]
		for _, t := range times {
			if t.After(cutoff) {
				valid = append(valid, t)
			}
		}
		if len(valid) == 0 {
			delete(rl.requests, k)
		} else {
			rl.requests[k] = valid
		}
	}
}
