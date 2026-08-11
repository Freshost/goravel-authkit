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

const DefaultAPITokensTable = "api_tokens"

type APITokensRepository interface {
	Create(ctx context.Context, token *models.APIToken) error
	FindBySelector(ctx context.Context, selector string) (*models.APIToken, error)
	ListByUser(ctx context.Context, userID uuid.UUID) ([]models.APIToken, error)
	CountActiveByUser(ctx context.Context, userID uuid.UUID, now time.Time) (int64, error)
	Revoke(ctx context.Context, id, userID uuid.UUID, now time.Time) (int64, error)
	RevokeAllByUser(ctx context.Context, userID uuid.UUID, now time.Time) error
	TouchLastUsed(ctx context.Context, id uuid.UUID, before, now time.Time) error
	DeletePrunable(ctx context.Context, before time.Time) error
}

type APITokens struct{ table string }

func NewAPITokens() *APITokens { return NewAPITokensWithTable(DefaultAPITokensTable) }

func NewAPITokensWithTable(table string) *APITokens {
	if table == "" {
		table = DefaultAPITokensTable
	}
	return &APITokens{table: table}
}

var _ APITokensRepository = (*APITokens)(nil)

func (r *APITokens) query(ctx context.Context) ormcontract.Query {
	return facades.Orm().WithContext(ctx).Query().Table(r.table)
}

func (r *APITokens) Create(ctx context.Context, token *models.APIToken) error {
	return r.query(ctx).Create(token)
}

func (r *APITokens) FindBySelector(ctx context.Context, selector string) (*models.APIToken, error) {
	var token models.APIToken
	err := r.query(ctx).Where("selector", selector).First(&token)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if token.ID == uuid.Nil {
		return nil, nil
	}
	return &token, nil
}

func (r *APITokens) ListByUser(ctx context.Context, userID uuid.UUID) ([]models.APIToken, error) {
	var tokens []models.APIToken
	err := r.query(ctx).Where("user_id", userID).WhereNull("revoked_at").Order("created_at desc").Find(&tokens)
	return tokens, err
}

func (r *APITokens) CountActiveByUser(ctx context.Context, userID uuid.UUID, now time.Time) (int64, error) {
	return r.query(ctx).Where("user_id", userID).WhereNull("revoked_at").Where("expires_at > ?", now).Count()
}

func (r *APITokens) Revoke(ctx context.Context, id, userID uuid.UUID, now time.Time) (int64, error) {
	res, err := r.query(ctx).Where("id", id).Where("user_id", userID).WhereNull("revoked_at").Update("revoked_at", now)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected, nil
}

func (r *APITokens) RevokeAllByUser(ctx context.Context, userID uuid.UUID, now time.Time) error {
	_, err := r.query(ctx).Where("user_id", userID).WhereNull("revoked_at").Update("revoked_at", now)
	return err
}

func (r *APITokens) TouchLastUsed(ctx context.Context, id uuid.UUID, before, now time.Time) error {
	_, err := r.query(ctx).Where("id", id).Where("last_used_at IS NULL OR last_used_at < ?", before).Update("last_used_at", now)
	return err
}

func (r *APITokens) DeletePrunable(ctx context.Context, before time.Time) error {
	_, err := r.query(ctx).Where("expires_at < ? OR (revoked_at IS NOT NULL AND revoked_at < ?)", before, before).Delete(&models.APIToken{})
	return err
}
