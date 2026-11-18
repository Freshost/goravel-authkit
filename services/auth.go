package services

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/freshost/goravel-authkit/models"
	"github.com/freshost/goravel-authkit/repositories"
)

// Auth encapsulates credential verification and self-service password changes.
// Session establishment itself is the controller's concern.
type Auth struct {
	repo      repositories.UsersRepository
	hasher    Hasher
	minPwLen  int
	dummyHash string
}

// NewAuth builds the auth service. minPwLen <= 0 falls back to
// DefaultMinPasswordLength.
func NewAuth(repo repositories.UsersRepository, hasher Hasher, minPwLen int) *Auth {
	if minPwLen <= 0 {
		minPwLen = DefaultMinPasswordLength
	}
	return &Auth{
		repo:     repo,
		hasher:   hasher,
		minPwLen: minPwLen,
		// A valid bcrypt hash of a random value, compared against when the email
		// is unknown to keep login timing roughly constant.
		dummyHash: "$2a$12$C6UzMDM.H6dfI/f/IKcEeO.iI1.Q/i.AqpKQ4dGz0qVqgD2Q1mQ1m",
	}
}

// Authenticate verifies credentials and returns the matching user. A generic
// ErrInvalidCredentials is returned for both unknown-email and wrong-password.
func (s *Auth) Authenticate(ctx context.Context, email, password string) (*models.User, error) {
	email = normalizeEmail(email)
	if validateEmail(email) != nil || password == "" {
		return nil, ErrInvalidCredentials
	}

	user, err := s.repo.FindByEmail(ctx, email)
	if err != nil {
		return nil, errors.Join(ErrInternal, err)
	}
	if user == nil || user.PasswordHash == nil || *user.PasswordHash == "" {
		// Dummy compare to keep timing roughly constant for unknown users.
		_ = s.hasher.Check(password, s.dummyHash)
		return nil, ErrInvalidCredentials
	}
	if !s.hasher.Check(password, *user.PasswordHash) {
		return nil, ErrInvalidCredentials
	}
	return user, nil
}

// Me returns the authenticated user, or ErrUnauthorized if it no longer exists or
// has been disabled. The disabled check mirrors the Authenticated middleware so the
// method is safe to use as a standalone "load current user" primitive.
func (s *Auth) Me(ctx context.Context, id uuid.UUID) (*models.User, error) {
	user, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, errors.Join(ErrInternal, err)
	}
	if user == nil || user.IsDisabled() {
		return nil, ErrUnauthorized
	}
	return user, nil
}

// UpdateProfile lets the authenticated user change their own name and email. The
// role is intentionally out of scope (admin-managed via the users service). It
// returns the updated user and whether anything actually changed (false skips
// the write so a no-op save isn't audited). A colliding email returns
// ErrAlreadyExists; a missing email returns ErrValidation. Changing the email
// clears EmailVerified, since the new address is unverified.
func (s *Auth) UpdateProfile(ctx context.Context, id uuid.UUID, email, name string) (*models.User, bool, error) {
	user, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, false, errors.Join(ErrInternal, err)
	}
	if user == nil {
		return nil, false, ErrUnauthorized
	}

	email = normalizeEmail(email)
	name = strings.TrimSpace(name)
	if err := validateEmail(email); err != nil {
		return nil, false, err
	}

	currentName := ""
	if user.Name != nil {
		currentName = *user.Name
	}
	emailChanged := email != user.Email
	nameChanged := name != currentName
	if !emailChanged && !nameChanged {
		return user, false, nil
	}

	if emailChanged {
		other, err := s.repo.FindByEmail(ctx, email)
		if err != nil {
			return nil, false, errors.Join(ErrInternal, err)
		}
		if other != nil && other.ID != user.ID {
			return nil, false, ErrAlreadyExists
		}
	}
	var namePtr *string
	if name != "" {
		namePtr = &name
	}

	if err := s.repo.UpdateProfile(ctx, user.ID, email, namePtr, emailChanged); err != nil {
		if isUniqueViolation(err) {
			return nil, false, ErrAlreadyExists
		}
		return nil, false, errors.Join(ErrInternal, err)
	}
	updated, err := s.repo.FindByID(ctx, user.ID)
	if err != nil {
		return nil, false, errors.Join(ErrInternal, err)
	}
	if updated == nil {
		return nil, false, ErrUnauthorized
	}
	return updated, true, nil
}

// isUniqueViolation best-effort detects a unique-constraint failure from the
// underlying driver, so a lost email-uniqueness race surfaces as 409 (not 500).
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "duplicate") || strings.Contains(msg, "unique")
}

// ChangePassword verifies the password proof and atomically replaces that exact
// credential version. The returned stored epoch keeps only this session alive.
func (s *Auth) ChangePassword(ctx context.Context, id uuid.UUID, currentPassword, newPassword string) (time.Time, error) {
	user, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return time.Time{}, errors.Join(ErrInternal, err)
	}
	if user == nil {
		return time.Time{}, ErrUnauthorized
	}

	if user.PasswordHash == nil || !s.hasher.Check(currentPassword, *user.PasswordHash) {
		return time.Time{}, ErrWrongPassword
	}
	if err := validatePassword(newPassword, s.minPwLen); err != nil {
		return time.Time{}, err
	}
	if newPassword == currentPassword {
		return time.Time{}, errors.Join(ErrValidation, errors.New("new password must differ from the current password"))
	}

	hashed, err := s.hasher.Make(newPassword)
	if err != nil {
		return time.Time{}, errors.Join(ErrInternal, err)
	}

	var changedAt time.Time
	err = s.repo.MutateLocked(ctx, id, func(current *models.User) error {
		if current.IsDisabled() || current.PasswordHash == nil || *current.PasswordHash != *user.PasswordHash || !current.PasswordChangedAt.Equal(user.PasswordChangedAt) {
			return ErrWrongPassword
		}
		current.AdvancePasswordEpoch(time.Now().UTC())
		current.PasswordHash = &hashed
		changedAt = current.PasswordChangedAt
		return nil
	})
	if err != nil {
		return time.Time{}, errors.Join(ErrInternal, err)
	}
	return changedAt, nil
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// PendingLogin validates the password proof retained while the second factor is pending.
func (s *Auth) PendingLogin(ctx context.Context, id uuid.UUID, stamp time.Time, mfa string, expires time.Time) (*models.User, error) {
	if !time.Now().Before(expires) {
		return nil, ErrUnauthorized
	}
	u, err := s.Me(ctx, id)
	if err != nil {
		return nil, err
	}
	if !u.PasswordChangedAt.Equal(stamp) || u.TwoFactorCredentialStamp() != mfa {
		return nil, ErrUnauthorized
	}
	return u, nil
}
