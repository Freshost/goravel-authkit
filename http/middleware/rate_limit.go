package middleware

import (
	nethttp "net/http"
	"sync"
	"time"

	contractshttp "github.com/goravel/framework/contracts/http"
)

// rateLimiter is a simple in-memory sliding-window limiter keyed by client IP.
// A single-process web tier makes this sufficient; no external store is needed.
type rateLimiter struct {
	mu       sync.Mutex
	requests map[string][]time.Time
}

var authLimiter = &rateLimiter{requests: make(map[string][]time.Time)}

// RateLimitAuth limits the login endpoint to maxAttempts per window per IP.
// Recommended: 5/min. Pass a large maxAttempts in local/dev env to relax it.
func RateLimitAuth(maxAttempts int, window time.Duration) contractshttp.Middleware {
	return func(ctx contractshttp.Context) {
		ip := ctx.Request().Ip()
		if authLimiter.isLimited(ip, maxAttempts, window) {
			_ = ctx.Response().Json(nethttp.StatusTooManyRequests, contractshttp.Json{
				"error":   "rate_limited",
				"message": "Too many attempts. Please try again later.",
			}).Abort()
			return
		}
		authLimiter.record(ip)
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

func (rl *rateLimiter) record(key string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.requests[key] = append(rl.requests[key], time.Now())
}

// ResetRateLimiters clears the limiter state (used by tests).
func ResetRateLimiters() {
	authLimiter.mu.Lock()
	authLimiter.requests = make(map[string][]time.Time)
	authLimiter.mu.Unlock()
}
