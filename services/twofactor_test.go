package services

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/freshost/goravel-authkit/models"
)

func seedFor2FA(repo *fakeRepo, email string) *models.User {
	u := &models.User{ID: uuid.New(), Email: email, Role: "admin"}
	repo.seed(u)
	return u
}

func newTwoFactor(repo *fakeRepo) *TwoFactor {
	// fakeCrypter is a no-op, so the stored secret equals the plaintext base32.
	return NewTwoFactor(repo, fakeCrypter{}, "TestApp", 8)
}

func TestTwoFactor_EnableConfirmVerify(t *testing.T) {
	repo := newFakeRepo()
	u := seedFor2FA(repo, "a@example.com")
	tf := newTwoFactor(repo)

	enr, err := tf.Enable(context.Background(), u.ID)
	require.NoError(t, err)
	require.NotEmpty(t, enr.Secret)
	assert.Contains(t, enr.OtpauthURL, "otpauth://")
	assert.False(t, repo.byID[u.ID].TwoFactorEnabled(), "pending, not yet confirmed")

	code, err := totp.GenerateCode(enr.Secret, time.Now())
	require.NoError(t, err)
	codes, err := tf.Confirm(context.Background(), u.ID, code)
	require.NoError(t, err)
	assert.Len(t, codes, 8)
	assert.True(t, repo.byID[u.ID].TwoFactorEnabled())

	code2, _ := totp.GenerateCode(enr.Secret, time.Now())
	ok, err := tf.Verify(repo.byID[u.ID], code2)
	require.NoError(t, err)
	assert.True(t, ok)

	ok, _ = tf.Verify(repo.byID[u.ID], "000000")
	assert.False(t, ok)
}

func TestTwoFactor_RecoveryCodeSingleUse(t *testing.T) {
	repo := newFakeRepo()
	u := seedFor2FA(repo, "b@example.com")
	tf := newTwoFactor(repo)
	enr, _ := tf.Enable(context.Background(), u.ID)
	code, _ := totp.GenerateCode(enr.Secret, time.Now())
	codes, err := tf.Confirm(context.Background(), u.ID, code)
	require.NoError(t, err)
	require.Len(t, codes, 8)

	ok, err := tf.ConsumeRecoveryCode(context.Background(), u.ID, codes[0])
	require.NoError(t, err)
	assert.True(t, ok, "first use succeeds")

	ok, err = tf.ConsumeRecoveryCode(context.Background(), u.ID, codes[0])
	require.NoError(t, err)
	assert.False(t, ok, "reuse fails")

	remaining, err := tf.RecoveryCodes(context.Background(), u.ID)
	require.NoError(t, err)
	assert.Len(t, remaining, 7)
}

func TestTwoFactor_ConfirmWrongCode(t *testing.T) {
	repo := newFakeRepo()
	u := seedFor2FA(repo, "c@example.com")
	tf := newTwoFactor(repo)
	_, err := tf.Enable(context.Background(), u.ID)
	require.NoError(t, err)
	_, err = tf.Confirm(context.Background(), u.ID, "000000")
	assert.ErrorIs(t, err, ErrInvalidCode)
}

func TestTwoFactor_Disable(t *testing.T) {
	repo := newFakeRepo()
	u := seedFor2FA(repo, "d@example.com")
	tf := newTwoFactor(repo)
	enr, _ := tf.Enable(context.Background(), u.ID)
	code, _ := totp.GenerateCode(enr.Secret, time.Now())
	_, err := tf.Confirm(context.Background(), u.ID, code)
	require.NoError(t, err)
	require.True(t, repo.byID[u.ID].TwoFactorEnabled())

	require.NoError(t, tf.Disable(context.Background(), u.ID))
	assert.False(t, repo.byID[u.ID].TwoFactorEnabled())
}

func TestTwoFactor_RegenerateInvalidatesOld(t *testing.T) {
	repo := newFakeRepo()
	u := seedFor2FA(repo, "e@example.com")
	tf := newTwoFactor(repo)
	enr, _ := tf.Enable(context.Background(), u.ID)
	code, _ := totp.GenerateCode(enr.Secret, time.Now())
	old, err := tf.Confirm(context.Background(), u.ID, code)
	require.NoError(t, err)

	fresh, err := tf.RegenerateRecoveryCodes(context.Background(), u.ID)
	require.NoError(t, err)
	assert.Len(t, fresh, 8)

	// an old code no longer works
	ok, err := tf.ConsumeRecoveryCode(context.Background(), u.ID, old[0])
	require.NoError(t, err)
	assert.False(t, ok)
}
