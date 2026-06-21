// Package repositories owns the GORM data access for goravel-authkit. Services
// depend on the UsersRepository interface so they can be unit-tested with a
// fake; the ORM-backed implementation uses the upstream Goravel facades.
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

// UsersRepository is the data-access seam for users. All methods take a
// context.Context first and return (nil, nil) — not an error — when a single
// record is not found, so services can map "not found" to their own sentinel.
type UsersRepository interface {
	FindByEmail(ctx context.Context, email string) (*models.User, error)
	FindByID(ctx context.Context, id uuid.UUID) (*models.User, error)
	List(ctx context.Context) ([]models.User, error)
	Count(ctx context.Context) (int64, error)
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

// Users is the ORM-backed UsersRepository.
type Users struct{}

// NewUsers returns an ORM-backed users repository.
func NewUsers() *Users {
	return &Users{}
}

var _ UsersRepository = (*Users)(nil)

func (r *Users) FindByEmail(ctx context.Context, email string) (*models.User, error) {
	var u models.User
	err := facades.Orm().WithContext(ctx).Query().Where("email", email).First(&u)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &u, nil
}

func (r *Users) FindByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	var u models.User
	err := facades.Orm().WithContext(ctx).Query().Where("id", id).First(&u)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &u, nil
}

func (r *Users) List(ctx context.Context) ([]models.User, error) {
	var users []models.User
	if err := facades.Orm().WithContext(ctx).Query().Order("created_at asc").Find(&users); err != nil {
		return nil, err
	}
	return users, nil
}

func (r *Users) Count(ctx context.Context) (int64, error) {
	return facades.Orm().WithContext(ctx).Query().Model(&models.User{}).Count()
}

func (r *Users) Create(ctx context.Context, u *models.User) error {
	return facades.Orm().WithContext(ctx).Query().Create(u)
}

func (r *Users) Save(ctx context.Context, u *models.User) error {
	return facades.Orm().WithContext(ctx).Query().Save(u)
}

func (r *Users) Delete(ctx context.Context, u *models.User) error {
	_, err := facades.Orm().WithContext(ctx).Query().Delete(u)
	return err
}

func (r *Users) UpdatePassword(ctx context.Context, id uuid.UUID, passwordHash string, changedAt time.Time) error {
	_, err := facades.Orm().WithContext(ctx).Query().Model(&models.User{}).Where("id", id).Update(map[string]any{
		"password_hash":       passwordHash,
		"password_changed_at": changedAt,
	})
	return err
}

func (r *Users) UpdateTwoFactor(ctx context.Context, id uuid.UUID, secret, recoveryCodes *string, confirmedAt *time.Time) error {
	_, err := facades.Orm().WithContext(ctx).Query().Model(&models.User{}).Where("id", id).Update(map[string]any{
		"two_factor_secret":         secret,
		"two_factor_recovery_codes": recoveryCodes,
		"two_factor_confirmed_at":   confirmedAt,
	})
	return err
}

func (r *Users) MutateLocked(ctx context.Context, id uuid.UUID, fn func(u *models.User) error) error {
	return facades.Orm().WithContext(ctx).Transaction(func(tx ormcontract.Query) error {
		var u models.User
		if err := tx.Where("id", id).LockForUpdate().First(&u); err != nil {
			return err
		}
		if u.ID == uuid.Nil {
			return gorm.ErrRecordNotFound
		}
		if err := fn(&u); err != nil {
			return err
		}
		return tx.Save(&u)
	})
}
