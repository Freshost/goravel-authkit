package feature

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/goravel/framework/facades"
	"github.com/stretchr/testify/require"

	authmodels "github.com/freshost/goravel-authkit/models"
	"github.com/freshost/goravel-authkit/repositories"
	"github.com/freshost/goravel-authkit/services"
)

func TestConcurrentDemotionsPreserveOneManagementUser(t *testing.T) {
	role := "race-admin-" + uuid.NewString()
	hash, err := facades.Hash().Make("password123")
	require.NoError(t, err)
	users := []*authmodels.User{
		{ID: uuid.New(), Email: uuid.NewString() + "@test.local", PasswordHash: &hash, PasswordChangedAt: time.Now().UTC(), Role: role},
		{ID: uuid.New(), Email: uuid.NewString() + "@test.local", PasswordHash: &hash, PasswordChangedAt: time.Now().UTC(), Role: role},
	}
	for _, user := range users {
		require.NoError(t, facades.Orm().Query().Create(user))
		defer func(id uuid.UUID) { _, _ = facades.Orm().Query().Where("id", id).Delete(&authmodels.User{}) }(user.ID)
	}

	svc := services.NewUsers(
		repositories.NewUsers(), services.NewFacadeHasher(), 8,
		[]string{role, "user"}, []string{role}, nil, true,
	)
	start := make(chan struct{})
	results := make(chan error, len(users))
	var wg sync.WaitGroup
	for _, user := range users {
		user := user
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := svc.Update(context.Background(), user.ID, user.Email, "", "user", nil, uuid.Nil)
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	var succeeded, refused int
	for err := range results {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, services.ErrLastAdmin):
			refused++
		default:
			require.NoError(t, err)
		}
	}
	require.Equal(t, 1, succeeded)
	require.Equal(t, 1, refused)

	count, err := repositories.NewUsers().CountActiveByRolesExcluding(context.Background(), []string{role}, uuid.Nil)
	require.NoError(t, err)
	require.EqualValues(t, 1, count)
}
