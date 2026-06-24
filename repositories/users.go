// Package repositories owns the GORM data access for goravel-authkit. Services
// depend on the UsersRepository interface so they can be unit-tested with a
// fake; the ORM-backed implementation uses the upstream Goravel facades.
//
// Every repository is bound to a concrete table name at construction. The bare
// New* constructors use the package default table; the *WithTable variants take
// an explicit name so two authkit instances can run over disjoint tables (e.g.
// "accounts" and "admin_users") in one app. The name is applied per query with
// GORM's .Table(name) — the idiomatic way to override a model's static table,
// since a Tabler TableName() result is cached and cannot vary per instance.
package repositories

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	ormcontract "github.com/goravel/framework/contracts/database/orm"
	"github.com/goravel/framework/facades"
	"gorm.io/gorm"

	"github.com/freshost/goravel-authkit/models"
)

// DefaultUsersTable is the table the bare NewUsers() constructor binds to.
const DefaultUsersTable = "users"

// UsersRepository is the data-access seam for users. All methods take a
// context.Context first and return (nil, nil) — not an error — when a single
// record is not found, so services can map "not found" to their own sentinel.
type UsersRepository interface {
	FindByEmail(ctx context.Context, email string) (*models.User, error)
	FindByID(ctx context.Context, id uuid.UUID) (*models.User, error)
	List(ctx context.Context) ([]models.User, error)
	Count(ctx context.Context) (int64, error)
	// CountActiveByRolesExcluding counts users whose role is in roles and whose
	// account is not disabled (disabled_at IS NULL), optionally excluding one id.
	// It backs the "keep at least one active admin" invariants. An empty roles
	// slice matches nothing (returns 0).
	CountActiveByRolesExcluding(ctx context.Context, roles []string, exclude uuid.UUID) (int64, error)
	Create(ctx context.Context, u *models.User) error
	Save(ctx context.Context, u *models.User) error
	Delete(ctx context.Context, u *models.User) error
	UpdatePassword(ctx context.Context, id uuid.UUID, passwordHash string, changedAt time.Time) error
	// UpdateTwoFactor sets the three two_factor columns (nil clears a column to NULL).
	UpdateTwoFactor(ctx context.Context, id uuid.UUID, secret, recoveryCodes *string, confirmedAt *time.Time) error
	// MutateLocked loads the user inside a transaction with a row lock
	// (SELECT ... FOR UPDATE), applies fn, and saves — making a read-modify-write
	// (e.g. consuming a recovery code, recording a used TOTP step) atomic.
	MutateLocked(ctx context.Context, id uuid.UUID, fn func(u *models.User) error) error
}

// Users is the ORM-backed UsersRepository, bound to a concrete table.
type Users struct{ table string }

// NewUsers returns an ORM-backed users repository over the default "users" table.
func NewUsers() *Users { return NewUsersWithTable(DefaultUsersTable) }

// NewUsersWithTable returns an ORM-backed users repository over the named table.
// An empty name falls back to the default so callers can pass through a
// zero-valued option safely.
func NewUsersWithTable(table string) *Users {
	if table == "" {
		table = DefaultUsersTable
	}
	return &Users{table: table}
}

var _ UsersRepository = (*Users)(nil)

func (r *Users) query(ctx context.Context) ormcontract.Query {
	return facades.Orm().WithContext(ctx).Query().Table(r.table)
}

func (r *Users) FindByEmail(ctx context.Context, email string) (*models.User, error) {
	var u models.User
	err := r.query(ctx).Where("email", email).First(&u)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	// Goravel's Query.First returns a nil error and leaves the destination
	// zero-valued when no row matches, so detect "not found" by the unset PK.
	if u.ID == uuid.Nil {
		return nil, nil
	}
	return &u, nil
}

func (r *Users) FindByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	var u models.User
	err := r.query(ctx).Where("id", id).First(&u)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if u.ID == uuid.Nil {
		return nil, nil
	}
	return &u, nil
}

func (r *Users) List(ctx context.Context) ([]models.User, error) {
	var users []models.User
	if err := r.query(ctx).Order("created_at asc").Find(&users); err != nil {
		return nil, err
	}
	return users, nil
}

func (r *Users) Count(ctx context.Context) (int64, error) {
	return r.query(ctx).Count()
}

func (r *Users) CountActiveByRolesExcluding(ctx context.Context, roles []string, exclude uuid.UUID) (int64, error) {
	if len(roles) == 0 {
		return 0, nil
	}
	q := r.query(ctx).
		Where("role IN ?", roles).
		WhereNull("disabled_at")
	if exclude != uuid.Nil {
		q = q.Where("id != ?", exclude)
	}
	return q.Count()
}

func (r *Users) Create(ctx context.Context, u *models.User) error {
	return r.query(ctx).Create(u)
}

func (r *Users) Save(ctx context.Context, u *models.User) error {
	return r.query(ctx).Save(u)
}

func (r *Users) Delete(ctx context.Context, u *models.User) error {
	_, err := r.query(ctx).Delete(u)
	return err
}

func (r *Users) UpdatePassword(ctx context.Context, id uuid.UUID, passwordHash string, changedAt time.Time) error {
	_, err := r.query(ctx).Where("id", id).Update(map[string]any{
		"password_hash":       passwordHash,
		"password_changed_at": changedAt,
	})
	return err
}

func (r *Users) UpdateTwoFactor(ctx context.Context, id uuid.UUID, secret, recoveryCodes *string, confirmedAt *time.Time) error {
	_, err := r.query(ctx).Where("id", id).Update(map[string]any{
		"two_factor_secret":         secret,
		"two_factor_recovery_codes": recoveryCodes,
		"two_factor_confirmed_at":   confirmedAt,
	})
	return err
}

func (r *Users) MutateLocked(ctx context.Context, id uuid.UUID, fn func(u *models.User) error) error {
	return facades.Orm().WithContext(ctx).Transaction(func(tx ormcontract.Query) error {
		var u models.User
		if err := tx.Table(r.table).Where("id", id).LockForUpdate().First(&u); err != nil {
			return err
		}
		if u.ID == uuid.Nil {
			return gorm.ErrRecordNotFound
		}
		if err := fn(&u); err != nil {
			return err
		}
		return tx.Table(r.table).Save(&u)
	})
}
