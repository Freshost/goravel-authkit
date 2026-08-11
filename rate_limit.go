package authkit

import "github.com/freshost/goravel-authkit/contracts"

// RateLimitStore is the backend contract for atomic rate-limit buckets.
type RateLimitStore = contracts.RateLimitStore

// RateLimitResult describes whether an attempt was accepted and, when denied,
// how long the caller should wait.
type RateLimitResult = contracts.RateLimitResult

// RegisterRateLimitStore installs a process-wide store before routes are
// registered. Use a shared implementation such as Redis in multi-instance apps.
func RegisterRateLimitStore(store RateLimitStore) {
	contracts.SetRateLimitStore(store)
}
