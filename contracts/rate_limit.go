package contracts

import (
	"context"
	"sync"
	"time"
)

// RateLimitResult is returned by an atomic rate-limit store operation.
type RateLimitResult struct {
	Allowed    bool
	RetryAfter time.Duration
}

// RateLimitStore atomically consumes one attempt from a named bucket. A shared
// implementation (for example Redis) makes limits effective across processes.
type RateLimitStore interface {
	Hit(ctx context.Context, key string, limit int, window time.Duration) (RateLimitResult, error)
}

var rateLimitStoreRegistry struct {
	sync.RWMutex
	store RateLimitStore
}

// SetRateLimitStore registers the process-wide host store used by route wiring.
func SetRateLimitStore(store RateLimitStore) {
	rateLimitStoreRegistry.Lock()
	defer rateLimitStoreRegistry.Unlock()
	rateLimitStoreRegistry.store = store
}

// RegisteredRateLimitStore returns the host store, or nil when none is set.
func RegisteredRateLimitStore() RateLimitStore {
	rateLimitStoreRegistry.RLock()
	defer rateLimitStoreRegistry.RUnlock()
	return rateLimitStoreRegistry.store
}
