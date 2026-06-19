package middleware

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRateLimiter_LimitsAfterMaxAttempts(t *testing.T) {
	rl := &rateLimiter{requests: make(map[string][]time.Time)}
	window := time.Minute

	// First 3 attempts are allowed; the limiter records each.
	for i := 0; i < 3; i++ {
		assert.False(t, rl.isLimited("1.2.3.4", 3, window), "attempt %d should not be limited", i)
		rl.record("1.2.3.4")
	}
	// The 4th check sees 3 recorded within the window → limited.
	assert.True(t, rl.isLimited("1.2.3.4", 3, window))

	// A different IP is independent.
	assert.False(t, rl.isLimited("5.6.7.8", 3, window))
}

func TestRateLimiter_WindowExpiry(t *testing.T) {
	rl := &rateLimiter{requests: make(map[string][]time.Time)}
	// Seed an old timestamp outside the window.
	rl.requests["1.2.3.4"] = []time.Time{time.Now().Add(-2 * time.Minute)}
	// With a 1-minute window the stale entry is pruned → not limited.
	assert.False(t, rl.isLimited("1.2.3.4", 1, time.Minute))
}
