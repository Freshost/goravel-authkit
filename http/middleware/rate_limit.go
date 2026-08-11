package middleware

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	contractshttp "github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	authcontracts "github.com/freshost/goravel-authkit/contracts"
)

// MemoryRateLimitStore is the default atomic sliding-window store. It is safe
// for concurrent use but process-local; multi-instance deployments should
// register a shared authkit.RateLimitStore implementation.
type MemoryRateLimitStore struct {
	mu        sync.Mutex
	requests  map[string][]time.Time
	lastSweep time.Time
}

// NewMemoryRateLimitStore creates an empty process-local store.
func NewMemoryRateLimitStore() *MemoryRateLimitStore {
	return &MemoryRateLimitStore{requests: make(map[string][]time.Time)}
}

var defaultRateLimitStore = NewMemoryRateLimitStore()

// DefaultRateLimitStore returns the shared process-local fallback store.
func DefaultRateLimitStore() authcontracts.RateLimitStore {
	return defaultRateLimitStore
}

// Hit atomically checks and records a sliding-window attempt.
func (store *MemoryRateLimitStore) Hit(_ context.Context, key string, limit int, window time.Duration) (authcontracts.RateLimitResult, error) {
	if key == "" || limit <= 0 || window <= 0 {
		return authcontracts.RateLimitResult{}, errors.New("invalid rate-limit bucket configuration")
	}
	store.mu.Lock()
	defer store.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-window)
	valid := store.requests[key][:0:0]
	for _, attemptedAt := range store.requests[key] {
		if attemptedAt.After(cutoff) {
			valid = append(valid, attemptedAt)
		}
	}
	store.requests[key] = valid

	if len(valid) >= limit {
		retryAfter := valid[0].Add(window).Sub(now)
		if retryAfter < time.Second {
			retryAfter = time.Second
		}
		return authcontracts.RateLimitResult{Allowed: false, RetryAfter: retryAfter}, nil
	}

	store.requests[key] = append(valid, now)
	if now.Sub(store.lastSweep) > window {
		store.sweepLocked(cutoff)
		store.lastSweep = now
	}

	return authcontracts.RateLimitResult{Allowed: true}, nil
}

func (store *MemoryRateLimitStore) sweepLocked(cutoff time.Time) {
	for key, attempts := range store.requests {
		valid := attempts[:0:0]
		for _, attemptedAt := range attempts {
			if attemptedAt.After(cutoff) {
				valid = append(valid, attemptedAt)
			}
		}
		if len(valid) == 0 {
			delete(store.requests, key)
		} else {
			store.requests[key] = valid
		}
	}
}

// AttemptLimiter namespaces and hashes bucket identifiers before passing them
// to the configured store, avoiding emails, IPs, and user IDs in backend keys.
type AttemptLimiter struct {
	store     authcontracts.RateLimitStore
	namespace string
	window    time.Duration
}

// NewAttemptLimiter creates the limiter used by one Authkit guard.
func NewAttemptLimiter(store authcontracts.RateLimitStore, namespace string, window time.Duration) *AttemptLimiter {
	return &AttemptLimiter{store: store, namespace: namespace, window: window}
}

// Hit consumes an attempt for the given dimension and identifier.
func (limiter *AttemptLimiter) Hit(ctx context.Context, dimension, identifier string, limit int) (authcontracts.RateLimitResult, error) {
	hash := sha256.Sum256([]byte(identifier))
	key := limiter.namespace + ":" + dimension + ":" + hex.EncodeToString(hash[:])
	return limiter.store.Hit(ctx, key, limit, limiter.window)
}

// RateLimitByIP applies the guard's IP bucket before the endpoint handler.
func RateLimitByIP(limiter *AttemptLimiter, attempts int) contractshttp.Middleware {
	return &rateLimitByIPMiddleware{limiter: limiter, attempts: attempts}
}

type rateLimitByIPMiddleware struct {
	limiter  *AttemptLimiter
	attempts int
}

func (middleware *rateLimitByIPMiddleware) Handle(ctx contractshttp.Context) {
	result, err := middleware.limiter.Hit(ctx.Context(), "ip", ctx.Request().Ip(), middleware.attempts)
	if err != nil {
		facades.Log().Errorf("authkit rate limiter: %v", err)
		_ = ctx.Response().Json(http.StatusServiceUnavailable, contractshttp.Json{
			"error": "rate_limiter_unavailable", "message": "Authentication is temporarily unavailable.",
		}).Abort()
		return
	}
	if !result.Allowed {
		ctx.Response().Header("Retry-After", strconv.Itoa(int((result.RetryAfter+time.Second-1)/time.Second)))
		_ = ctx.Response().Json(http.StatusTooManyRequests, contractshttp.Json{
			"error": "rate_limited", "message": "Too many attempts. Please try again later.",
		}).Abort()
		return
	}
	ctx.Request().Next()
}

func (middleware *rateLimitByIPMiddleware) Signature() string {
	return "goravel-authkit.rate-limit-by-ip"
}
