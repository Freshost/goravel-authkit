package feature

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/goravel/framework/facades"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/freshost/goravel-authkit/models"
	"github.com/freshost/goravel-authkit/repositories"
	"github.com/freshost/goravel-authkit/services"
)

func credentialUser(t *testing.T) *models.User {
	t.Helper()
	hash, err := facades.Hash().Make("password123")
	require.NoError(t, err)
	user := &models.User{ID: uuid.New(), Email: uuid.NewString() + "@test.local", PasswordHash: &hash, PasswordChangedAt: time.Now().UTC().Truncate(time.Microsecond), Role: "user"}
	require.NoError(t, repositories.NewUsers().Create(context.Background(), user))
	t.Cleanup(func() { _, _ = facades.Orm().Query().Where("id", user.ID).Delete(&models.User{}) })
	return user
}

func TestConcurrentPersonalTokenQuotaIsAtomic(t *testing.T) {
	user := credentialUser(t)
	repo := repositories.NewAPITokens()
	svc := services.NewAPITokens(repo, repositories.NewUsers(), services.NewFacadeHasher(), nil, nil, time.Hour, 1, true)
	t.Cleanup(func() { _, _ = facades.Orm().Query().Where("user_id", user.ID).Delete(&models.APIToken{}) })
	start, results := make(chan struct{}), make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := svc.Issue(context.Background(), services.IssueAPITokenCommand{UserID: user.ID, Name: "Concurrent", Password: "password123", ExpiresAt: time.Now().Add(30 * time.Minute)})
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	created, refused := 0, 0
	for err := range results {
		if err == nil {
			created++
		} else {
			require.ErrorIs(t, err, services.ErrTokenLimit)
			refused++
		}
	}
	require.Equal(t, 1, created)
	require.Equal(t, 1, refused)
}

func TestMFARegenerationCannotRestoreDisabledCredential(t *testing.T) {
	user := credentialUser(t)
	repo := repositories.NewUsers()
	tf := services.NewTwoFactor(repo, services.NewFacadeCrypter(), "CI", 8)
	for i := 0; i < 10; i++ {
		enrollment, err := tf.Enable(context.Background(), user.ID)
		require.NoError(t, err)
		code, err := totp.GenerateCode(enrollment.Secret, time.Now())
		require.NoError(t, err)
		_, err = tf.Confirm(context.Background(), user.ID, code)
		require.NoError(t, err)
		start, results := make(chan struct{}), make(chan error, 2)
		go func() { <-start; _, err := tf.RegenerateRecoveryCodes(context.Background(), user.ID); results <- err }()
		go func() { <-start; results <- tf.Disable(context.Background(), user.ID) }()
		close(start)
		for j := 0; j < 2; j++ {
			err := <-results
			if err != nil {
				require.ErrorIs(t, err, services.ErrTwoFactorNotEnrolled)
			}
		}
		current, err := repo.FindByID(context.Background(), user.ID)
		require.NoError(t, err)
		require.False(t, current.TwoFactorEnabled())
	}
}

func TestRememberRestoreAndTerminationHaveOneOutcome(t *testing.T) {
	user := credentialUser(t)
	remember := services.NewRemember(repositories.NewRemember(), time.Hour)
	repo := repositories.NewSessions()
	sessions := services.NewSessions(repo, time.Hour)
	t.Cleanup(func() { _ = repo.DeleteByUser(context.Background(), user.ID) })
	for i := 0; i < 10; i++ {
		binding := uuid.NewString()
		value, err := remember.IssueVerified(context.Background(), user.ID, user.PasswordChangedAt, binding)
		require.NoError(t, err)
		credential, _, err := remember.ResolveVerified(context.Background(), value)
		require.NoError(t, err)
		require.NoError(t, sessions.Track(context.Background(), binding, user.ID, "", "", credential.Selector))
		start, restored, revoked := make(chan struct{}), make(chan error, 1), make(chan error, 1)
		go func() {
			<-start
			restored <- sessions.Track(context.Background(), binding, user.ID, "", "", credential.Selector)
		}()
		go func() { <-start; revoked <- repo.DeleteBySessionID(context.Background(), binding) }()
		close(start)
		require.NoError(t, <-revoked)
		if err := <-restored; err != nil {
			require.ErrorIs(t, err, gorm.ErrRecordNotFound)
		}
		_, _, err = remember.ResolveVerified(context.Background(), value)
		require.Error(t, err)
		alive, err := sessions.Touch(context.Background(), binding)
		require.NoError(t, err)
		require.False(t, alive)
	}
}

func TestPrunedSessionStillRevokesRememberBinding(t *testing.T) {
	user := credentialUser(t)
	remember := services.NewRemember(repositories.NewRemember(), time.Hour)
	binding := uuid.NewString()
	cookie, err := remember.IssueVerified(context.Background(), user.ID, user.PasswordChangedAt, binding)
	require.NoError(t, err)
	credential, _, err := remember.ResolveVerified(context.Background(), cookie)
	require.NoError(t, err)
	sessions := services.NewSessions(repositories.NewSessions(), time.Hour)
	require.NoError(t, sessions.Track(context.Background(), binding, user.ID, "", "", credential.Selector))
	// Pruning removes only tracking, while a remembered browser may return later.
	_, err = facades.Orm().Query().Table("auth_sessions").Where("session_id", binding).Update("last_active_at", time.Now().Add(-365*24*time.Hour))
	require.NoError(t, err)
	require.NoError(t, repositories.NewSessions().DeleteStale(context.Background(), time.Now().Add(-180*24*time.Hour)))
	require.NoError(t, repositories.NewSessions().DeleteBySessionID(context.Background(), binding))
	_, _, err = remember.ResolveVerified(context.Background(), cookie)
	require.Error(t, err)
}

func TestRememberPruningUsesEachGuardAndConfiguredLifetime(t *testing.T) {
	user := credentialUser(t)
	oldLifetime := facades.Config().Get("session.lifetime")
	facades.Config().Add("session.lifetime", 24*60)
	defer facades.Config().Add("session.lifetime", oldLifetime)
	for _, tables := range []struct{ remember, sessions string }{{"auth_remember_tokens", "auth_sessions"}, {"client_remember_tokens", "client_auth_sessions"}} {
		credential := &models.RememberToken{ID: uuid.New(), UserID: user.ID, Selector: uuid.NewString(), ValidatorHash: "expired", ExpiresAt: time.Now().Add(-time.Hour), CreatedAt: time.Now().Add(-48 * time.Hour)}
		require.NoError(t, facades.Orm().Query().Table(tables.remember).Create(credential))
		session := &models.AuthSession{ID: uuid.New(), SessionID: uuid.NewString(), UserID: user.ID, LastActiveAt: time.Now().Add(-3 * time.Hour)}
		require.NoError(t, facades.Orm().Query().Table(tables.sessions).Create(session))
		defer facades.Orm().Query().Table(tables.sessions).Where("id", session.ID).Delete(&models.AuthSession{})
	}
	require.NoError(t, facades.Artisan().Call("auth:prune-remember-tokens"))
	for _, table := range []string{"auth_remember_tokens", "client_remember_tokens"} {
		count, err := facades.Orm().Query().Table(table).Where("user_id", user.ID).Count()
		require.NoError(t, err)
		require.Zero(t, count)
	}
	for _, table := range []string{"auth_sessions", "client_auth_sessions"} {
		count, err := facades.Orm().Query().Table(table).Where("user_id", user.ID).Count()
		require.NoError(t, err)
		require.EqualValues(t, 1, count)
	}
}

func TestManagedEmailVerificationIsNotCopiedToReplacement(t *testing.T) {
	user := credentialUser(t)
	now := time.Now()
	_, err := facades.Orm().Query().Model(&models.User{}).Where("id", user.ID).Update("email_verified", now)
	require.NoError(t, err)
	svc := services.NewUsers(repositories.NewUsers(), services.NewFacadeHasher(), 8, nil, []string{"admin"}, nil, true)
	updated, err := svc.Update(context.Background(), user.ID, user.Email, "name", "user", nil, uuid.Nil)
	require.NoError(t, err)
	require.NotNil(t, updated.EmailVerified)
	updated, err = svc.Update(context.Background(), user.ID, uuid.NewString()+"@test.local", "name", "user", nil, uuid.Nil)
	require.NoError(t, err)
	require.Nil(t, updated.EmailVerified)
}
