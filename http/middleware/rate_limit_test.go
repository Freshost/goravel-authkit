package middleware

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	authcontracts "github.com/freshost/goravel-authkit/contracts"
)

func TestMemoryRateLimitStoreLimitsAtomically(t *testing.T) {
	store := NewMemoryRateLimitStore()

	for range 3 {
		result, err := store.Hit(context.Background(), "login", 3, time.Minute)
		require.NoError(t, err)
		assert.True(t, result.Allowed)
	}
	result, err := store.Hit(context.Background(), "login", 3, time.Minute)
	require.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.Positive(t, result.RetryAfter)
}

func TestMemoryRateLimitStoreIsConcurrentSafe(t *testing.T) {
	store := NewMemoryRateLimitStore()
	const limit = 10
	var allowed int
	var mu sync.Mutex
	var wait sync.WaitGroup

	for range 100 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, err := store.Hit(context.Background(), "shared", limit, time.Minute)
			require.NoError(t, err)
			if result.Allowed {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	wait.Wait()
	assert.Equal(t, limit, allowed)
}

func TestMemoryRateLimitStoreExpiresWindow(t *testing.T) {
	store := NewMemoryRateLimitStore()
	store.requests["key"] = []time.Time{time.Now().Add(-2 * time.Minute)}

	result, err := store.Hit(context.Background(), "key", 1, time.Minute)
	require.NoError(t, err)
	assert.True(t, result.Allowed)
}

func TestAttemptLimiterHashesAndNamespacesIdentifiers(t *testing.T) {
	store := &capturingRateLimitStore{}
	limiter := NewAttemptLimiter(store, "authkit:admin", time.Minute)

	_, err := limiter.Hit(context.Background(), "login-account", "person@example.com", 5)
	require.NoError(t, err)
	assert.Contains(t, store.key, "authkit:admin:login-account:")
	assert.NotContains(t, store.key, "person@example.com")
}

func TestAttemptLimiterKeepsDimensionsAndGuardsIndependent(t *testing.T) {
	store := NewMemoryRateLimitStore()
	admin := NewAttemptLimiter(store, "authkit:admin", time.Minute)
	client := NewAttemptLimiter(store, "authkit:client", time.Minute)

	first, err := admin.Hit(context.Background(), "login-account", "person@example.com", 1)
	require.NoError(t, err)
	assert.True(t, first.Allowed)
	second, err := admin.Hit(context.Background(), "login-account", "person@example.com", 1)
	require.NoError(t, err)
	assert.False(t, second.Allowed)

	otherDimension, err := admin.Hit(context.Background(), "ip", "person@example.com", 1)
	require.NoError(t, err)
	assert.True(t, otherDimension.Allowed)
	otherGuard, err := client.Hit(context.Background(), "login-account", "person@example.com", 1)
	require.NoError(t, err)
	assert.True(t, otherGuard.Allowed)
}

func TestAttemptLimiterPropagatesStoreFailure(t *testing.T) {
	store := &capturingRateLimitStore{err: errors.New("redis unavailable")}
	limiter := NewAttemptLimiter(store, "authkit:admin", time.Minute)

	_, err := limiter.Hit(context.Background(), "ip", "127.0.0.1", 5)
	assert.EqualError(t, err, "redis unavailable")
}

type capturingRateLimitStore struct {
	key string
	err error
}

func (store *capturingRateLimitStore) Hit(_ context.Context, key string, _ int, _ time.Duration) (authcontracts.RateLimitResult, error) {
	store.key = key
	return authcontracts.RateLimitResult{Allowed: true}, store.err
}
