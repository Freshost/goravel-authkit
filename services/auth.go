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
	if email == "" || password == "" {
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

// Me returns the authenticated user, or ErrUnauthorized if it no longer exists.
func (s *Auth) Me(ctx context.Context, id uuid.UUID) (*models.User, error) {
	user, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, errors.Join(ErrInternal, err)
	}
	if user == nil {
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
	if email == "" {
		return nil, false, errors.Join(ErrValidation, errors.New("email is required"))
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
		user.Email = email
		user.EmailVerified = nil
	}
	if name != "" {
		user.Name = &name
	} else {
		user.Name = nil
	}

	if err := s.repo.Save(ctx, user); err != nil {
		if isUniqueViolation(err) {
			return nil, false, ErrAlreadyExists
		}
		return nil, false, errors.Join(ErrInternal, err)
	}
	return user, true, nil
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

// ChangePassword verifies the current password, validates the new one (min
// length, must differ), updates the hash, and bumps password_changed_at so
// every OTHER active session for this user is rejected on its next request. It
// returns the new password_changed_at so the controller can re-stamp THIS
// session and keep it alive.
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
	if len([]rune(newPassword)) < s.minPwLen {
		return time.Time{}, errors.Join(ErrValidation, errors.New("new password is too short"))
	}
	if newPassword == currentPassword {
		return time.Time{}, errors.Join(ErrValidation, errors.New("new password must differ from the current password"))
	}

	hashed, err := s.hasher.Make(newPassword)
	if err != nil {
		return time.Time{}, errors.Join(ErrInternal, err)
	}

	changedAt := time.Now().UTC()
	if err := s.repo.UpdatePassword(ctx, id, hashed, changedAt); err != nil {
		return time.Time{}, errors.Join(ErrInternal, err)
	}
	return changedAt, nil
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
