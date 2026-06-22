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

// DefaultRole is assigned to users created without an explicit role.
const DefaultRole = "admin"

// Users orchestrates admin user-management use cases and owns their validation.
type Users struct {
	repo     repositories.UsersRepository
	hasher   Hasher
	minPwLen int
	roles    []string
}

// NewUsers builds the user-management service. minPwLen <= 0 falls back to
// DefaultMinPasswordLength. roles, when non-empty, restricts the accepted role
// values (Create/Update reject anything outside the set); empty means any role.
func NewUsers(repo repositories.UsersRepository, hasher Hasher, minPwLen int, roles []string) *Users {
	if minPwLen <= 0 {
		minPwLen = DefaultMinPasswordLength
	}
	return &Users{repo: repo, hasher: hasher, minPwLen: minPwLen, roles: roles}
}

// defaultRole returns the role to assign when none is given: the first
// configured role, else DefaultRole.
func (s *Users) defaultRole() string {
	if len(s.roles) > 0 {
		return s.roles[0]
	}
	return DefaultRole
}

// roleAllowed reports whether role is acceptable. With no configured roles any
// non-empty role is allowed.
func (s *Users) roleAllowed(role string) bool {
	if len(s.roles) == 0 {
		return true
	}
	for _, r := range s.roles {
		if r == role {
			return true
		}
	}
	return false
}

// GetByID returns a user or ErrNotFound.
func (s *Users) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	u, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, errors.Join(ErrInternal, err)
	}
	if u == nil {
		return nil, ErrNotFound
	}
	return u, nil
}

// List returns all users ordered by creation time.
func (s *Users) List(ctx context.Context) ([]models.User, error) {
	users, err := s.repo.List(ctx)
	if err != nil {
		return nil, errors.Join(ErrInternal, err)
	}
	return users, nil
}

// Create validates input and inserts a new user. Idempotent callers (e.g. a
// bootstrap command) should check for ErrAlreadyExists.
func (s *Users) Create(ctx context.Context, email, name, password, role string) (*models.User, error) {
	email = normalizeEmail(email)
	name = strings.TrimSpace(name)
	role = strings.TrimSpace(role)
	if email == "" || password == "" {
		return nil, errors.Join(ErrValidation, errors.New("email and password are required"))
	}
	if len([]rune(password)) < s.minPwLen {
		return nil, errors.Join(ErrValidation, errors.New("password is too short"))
	}
	if role == "" {
		role = s.defaultRole()
	}
	if !s.roleAllowed(role) {
		return nil, errors.Join(ErrValidation, errors.New("invalid role"))
	}

	existing, err := s.repo.FindByEmail(ctx, email)
	if err != nil {
		return nil, errors.Join(ErrInternal, err)
	}
	if existing != nil {
		return nil, ErrAlreadyExists
	}

	hashed, err := s.hasher.Make(password)
	if err != nil {
		return nil, errors.Join(ErrInternal, err)
	}

	now := time.Now().UTC()
	var namePtr *string
	if name != "" {
		namePtr = &name
	}
	u := &models.User{
		ID:                uuid.New(),
		Email:             email,
		Name:              namePtr,
		PasswordHash:      &hashed,
		PasswordChangedAt: now,
		Role:              role,
	}
	if err := s.repo.Create(ctx, u); err != nil {
		return nil, errors.Join(ErrInternal, err)
	}
	return u, nil
}

// Update changes a user's email, name, and role (not the password).
func (s *Users) Update(ctx context.Context, id uuid.UUID, email, name, role string) (*models.User, error) {
	u, err := s.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	email = normalizeEmail(email)
	name = strings.TrimSpace(name)
	role = strings.TrimSpace(role)
	if email == "" {
		return nil, errors.Join(ErrValidation, errors.New("email is required"))
	}
	if role != "" && !s.roleAllowed(role) {
		return nil, errors.Join(ErrValidation, errors.New("invalid role"))
	}

	if email != u.Email {
		other, err := s.repo.FindByEmail(ctx, email)
		if err != nil {
			return nil, errors.Join(ErrInternal, err)
		}
		if other != nil && other.ID != u.ID {
			return nil, ErrAlreadyExists
		}
	}

	u.Email = email
	if name != "" {
		u.Name = &name
	} else {
		u.Name = nil
	}
	if role != "" {
		u.Role = role
	}
	if err := s.repo.Save(ctx, u); err != nil {
		return nil, errors.Join(ErrInternal, err)
	}
	return u, nil
}

// Delete removes a user, refusing to remove the last one.
func (s *Users) Delete(ctx context.Context, id uuid.UUID) error {
	u, err := s.GetByID(ctx, id)
	if err != nil {
		return err
	}
	count, err := s.repo.Count(ctx)
	if err != nil {
		return errors.Join(ErrInternal, err)
	}
	if count <= 1 {
		return ErrLastAdmin
	}
	if err := s.repo.Delete(ctx, u); err != nil {
		return errors.Join(ErrInternal, err)
	}
	return nil
}

// SetPassword resets a user's password (admin action). It bumps
// password_changed_at, which invalidates that user's existing sessions.
func (s *Users) SetPassword(ctx context.Context, id uuid.UUID, newPassword string) (*models.User, error) {
	u, err := s.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if len([]rune(newPassword)) < s.minPwLen {
		return nil, errors.Join(ErrValidation, errors.New("password is too short"))
	}
	hashed, err := s.hasher.Make(newPassword)
	if err != nil {
		return nil, errors.Join(ErrInternal, err)
	}
	changedAt := time.Now().UTC()
	if err := s.repo.UpdatePassword(ctx, id, hashed, changedAt); err != nil {
		return nil, errors.Join(ErrInternal, err)
	}
	u.PasswordHash = &hashed
	u.PasswordChangedAt = changedAt
	return u, nil
}
