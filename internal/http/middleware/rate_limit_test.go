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
		rl.record("1.2.3.4", window)
	}
	// The 4th check sees 3 recorded within the window → limited.
	assert.True(t, rl.isLimited("1.2.3.4", 3, window))

	// A different IP is independent.
	assert.False(t, rl.isLimited("5.6.7.8", 3, window))
}

func TestRateLimiter_SweepEvictsStaleIPs(t *testing.T) {
	rl := &rateLimiter{requests: make(map[string][]time.Time)}
	// Seed many IPs with timestamps already outside the window.
	for i := 0; i < 100; i++ {
		rl.requests[string(rune(i))] = []time.Time{time.Now().Add(-2 * time.Minute)}
	}
	// Force lastSweep into the past so the next record triggers a sweep.
	rl.lastSweep = time.Now().Add(-2 * time.Minute)

	rl.record("fresh-ip", time.Minute)

	// All stale IPs are evicted; only the fresh one remains.
	assert.Len(t, rl.requests, 1)
	_, ok := rl.requests["fresh-ip"]
	assert.True(t, ok)
}

func TestRateLimiter_WindowExpiry(t *testing.T) {
	rl := &rateLimiter{requests: make(map[string][]time.Time)}
	// Seed an old timestamp outside the window.
	rl.requests["1.2.3.4"] = []time.Time{time.Now().Add(-2 * time.Minute)}
	// With a 1-minute window the stale entry is pruned → not limited.
	assert.False(t, rl.isLimited("1.2.3.4", 1, time.Minute))
}
