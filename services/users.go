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

// DefaultRole is the non-privileged role assigned to users created without an
// explicit role when no safer configured role can be derived. It must never be
// a management/admin role: new users default to the least privilege.
const DefaultRole = "user"

// AdminRole is the canonical privileged role. It is the fail-closed default for
// the /users management gate and the bootstrap (auth:create-user) admin.
const AdminRole = "admin"

// Users orchestrates admin user-management use cases and owns their validation.
type Users struct {
	repo            repositories.UsersRepository
	hasher          Hasher
	minPwLen        int
	roles           []string
	managementRoles []string
}

// NewUsers builds the user-management service. minPwLen <= 0 falls back to
// DefaultMinPasswordLength. roles, when non-empty, restricts the accepted role
// values (Create/Update reject anything outside the set); empty means any role.
// managementRoles is the set of privileged roles (those that can manage users);
// it backs the "default new users to non-admin" choice and the "keep at least
// one active admin" invariants on delete/disable/demote.
func NewUsers(repo repositories.UsersRepository, hasher Hasher, minPwLen int, roles, managementRoles []string) *Users {
	if minPwLen <= 0 {
		minPwLen = DefaultMinPasswordLength
	}
	return &Users{repo: repo, hasher: hasher, minPwLen: minPwLen, roles: roles, managementRoles: managementRoles}
}

// isManagementRole reports whether role is one of the privileged (admin)
// management roles.
func (s *Users) isManagementRole(role string) bool {
	for _, r := range s.managementRoles {
		if r == role {
			return true
		}
	}
	return false
}

// defaultRole returns the NON-privileged role to assign when none is given: the
// first configured role that is not a management role, else DefaultRole. It must
// never return an admin role, so a created user can't silently gain privileges.
func (s *Users) defaultRole() string {
	for _, r := range s.roles {
		if !s.isManagementRole(r) {
			return r
		}
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
	if email == "" {
		return nil, errors.Join(ErrValidation, errors.New("email is required"))
	}
	if err := validatePassword(password, s.minPwLen); err != nil {
		return nil, err
	}
	// Default to a non-privileged role; never silently mint an admin.
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

// Update changes a user's email, name, and role (not the password). disabled,
// when non-nil, locks (true) or unlocks (false) the account; nil leaves the lock
// state untouched. It enforces two invariants on a user who currently holds a
// management role: it cannot self-disable, and it cannot be disabled or demoted
// away from its management role if it is the last active admin (ErrLastAdmin).
func (s *Users) Update(ctx context.Context, id uuid.UUID, email, name, role string, disabled *bool, actorID uuid.UUID) (*models.User, error) {
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

	// Guard the active-admin invariant before any mutation. Only relevant when
	// the target currently holds a management role and is currently active.
	wasManagement := s.isManagementRole(u.Role) && !u.IsDisabled()
	if wasManagement {
		disabling := disabled != nil && *disabled
		demoting := role != "" && !s.isManagementRole(role)
		if disabling || demoting {
			// Self-disable is always refused (mirrors the controller guard so a
			// non-controller caller can't bypass it).
			if disabling && actorID != uuid.Nil && actorID == id {
				return nil, errors.Join(ErrValidation, errors.New("you cannot disable your own account"))
			}
			others, err := s.repo.CountActiveByRolesExcluding(ctx, s.managementRoles, id)
			if err != nil {
				return nil, errors.Join(ErrInternal, err)
			}
			if others == 0 {
				return nil, ErrLastAdmin
			}
		}
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
	if disabled != nil {
		switch {
		case *disabled && u.DisabledAt == nil:
			now := time.Now().UTC()
			u.DisabledAt = &now
		case !*disabled:
			u.DisabledAt = nil
		}
	}
	if err := s.repo.Save(ctx, u); err != nil {
		return nil, errors.Join(ErrInternal, err)
	}
	return u, nil
}

// Delete removes a user, refusing to remove the last active admin. The guard
// counts users holding a management role (not total rows): deleting a
// management user is refused when no OTHER active management user remains.
func (s *Users) Delete(ctx context.Context, id uuid.UUID) error {
	u, err := s.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if s.isManagementRole(u.Role) {
		others, err := s.repo.CountActiveByRolesExcluding(ctx, s.managementRoles, id)
		if err != nil {
			return errors.Join(ErrInternal, err)
		}
		if others == 0 {
			return ErrLastAdmin
		}
	} else if len(s.managementRoles) == 0 {
		// No management roles configured: fall back to the legacy "never remove
		// the last remaining user" guard so a single-user install stays usable.
		count, err := s.repo.Count(ctx)
		if err != nil {
			return errors.Join(ErrInternal, err)
		}
		if count <= 1 {
			return ErrLastAdmin
		}
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
	if err := validatePassword(newPassword, s.minPwLen); err != nil {
		return nil, err
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

// validatePassword enforces the shared password rules used wherever a new
// password is accepted (create, admin reset, self-service change): non-empty
// (rejecting all-whitespace), at least minLen runes, and at most MaxPasswordBytes
// bytes so bcrypt never silently truncates a longer secret. It returns an
// ErrValidation-wrapped error with a human-readable message, or nil when valid.
func validatePassword(password string, minLen int) error {
	if strings.TrimSpace(password) == "" {
		return errors.Join(ErrValidation, errors.New("password is required"))
	}
	if len([]rune(password)) < minLen {
		return errors.Join(ErrValidation, errors.New("password is too short"))
	}
	if len(password) > MaxPasswordBytes {
		return errors.Join(ErrValidation, errors.New("password is too long"))
	}
	return nil
}
