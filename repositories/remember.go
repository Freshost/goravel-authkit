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

// DefaultRememberTokensTable is the table the bare NewRemember() constructor binds to.
const DefaultRememberTokensTable = "auth_remember_tokens"

// RememberRepository is the data-access seam for "remember me" tokens. As with
// UsersRepository, FindBySelector returns (nil, nil) — not an error — when no row
// matches, so the service maps "not found" to its own sentinel.
type RememberRepository interface {
	Create(ctx context.Context, t *models.RememberToken) error
	FindBySelector(ctx context.Context, selector string) (*models.RememberToken, error)
	// RotateValidator atomically swaps the validator only if the row still holds
	// expectedCurrentHash (a compare-and-set), moving it to previous_validator_hash
	// and sliding the expiry. Returns the number of rows updated (0 = another
	// request already rotated it, so the caller must not treat the mismatch as
	// theft).
	RotateValidator(ctx context.Context, id uuid.UUID, expectedCurrentHash, newCurrentHash, newPreviousHash string, rotatedAt, expiresAt time.Time) (int64, error)
	Delete(ctx context.Context, id uuid.UUID) error
	DeleteByUser(ctx context.Context, userID uuid.UUID) error
	DeleteExpired(ctx context.Context, now time.Time) error
}

// Remember is the ORM-backed RememberRepository, bound to a concrete table.
type Remember struct{ table string }

// NewRemember returns an ORM-backed remember-token repository over the default table.
func NewRemember() *Remember { return NewRememberWithTable(DefaultRememberTokensTable) }

// NewRememberWithTable returns an ORM-backed remember-token repository over the named table.
func NewRememberWithTable(table string) *Remember {
	if table == "" {
		table = DefaultRememberTokensTable
	}
	return &Remember{table: table}
}

var _ RememberRepository = (*Remember)(nil)

func (r *Remember) query(ctx context.Context) ormcontract.Query {
	return facades.Orm().WithContext(ctx).Query().Table(r.table)
}

func (r *Remember) Create(ctx context.Context, t *models.RememberToken) error {
	return r.query(ctx).Create(t)
}

func (r *Remember) FindBySelector(ctx context.Context, selector string) (*models.RememberToken, error) {
	var t models.RememberToken
	err := r.query(ctx).Where("selector", selector).First(&t)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	// Goravel's Query.First leaves the destination zero-valued (nil error) on no
	// match, so detect "not found" by the unset PK.
	if t.ID == uuid.Nil {
		return nil, nil
	}
	return &t, nil
}

func (r *Remember) RotateValidator(ctx context.Context, id uuid.UUID, expectedCurrentHash, newCurrentHash, newPreviousHash string, rotatedAt, expiresAt time.Time) (int64, error) {
	res, err := r.query(ctx).
		Where("id", id).Where("validator_hash", expectedCurrentHash).
		Update(map[string]any{
			"validator_hash":          newCurrentHash,
			"previous_validator_hash": newPreviousHash,
			"rotated_at":              rotatedAt,
			"expires_at":              expiresAt,
		})
	if err != nil {
		return 0, err
	}
	return res.RowsAffected, nil
}

func (r *Remember) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.query(ctx).Where("id", id).Delete(&models.RememberToken{})
	return err
}

func (r *Remember) DeleteByUser(ctx context.Context, userID uuid.UUID) error {
	_, err := r.query(ctx).Where("user_id", userID).Delete(&models.RememberToken{})
	return err
}

func (r *Remember) DeleteExpired(ctx context.Context, now time.Time) error {
	_, err := r.query(ctx).Where("expires_at < ?", now).Delete(&models.RememberToken{})
	return err
}
