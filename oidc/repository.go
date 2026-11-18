package oidc

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	orm "github.com/goravel/framework/contracts/database/orm"
	"github.com/goravel/framework/facades"
	"gorm.io/gorm"
)

const (
	clientsTable  = "authkit_oidc_clients"
	requestsTable = "authkit_oidc_requests"
	grantsTable   = "authkit_oidc_grants"
	tokensTable   = "authkit_oidc_tokens"
)

// Store confines ORM details and supplies transaction-bound repositories.
type Store interface {
	Transaction(context.Context, func(Store) error) error
	Client(context.Context, string, bool) (*Client, error)
	CreateClient(context.Context, *Client) error
	SaveClient(context.Context, *Client) error
	Request(context.Context, string, bool) (*authorization, error)
	RequestByCode(context.Context, string) (*authorization, error)
	SaveRequest(context.Context, *authorization) error
	Grant(context.Context, string, bool) (*Connection, error)
	SaveGrant(context.Context, *Connection) error
	Token(context.Context, string, bool) (*token, error)
	Refresh(context.Context, string, bool) (*token, error)
	SaveToken(context.Context, *token) error
	Connections(context.Context, uuid.UUID) ([]Connection, error)
	RevokeUser(context.Context, uuid.UUID, time.Time) error
	Prune(context.Context, time.Time) error
}

type databaseStore struct {
	issuer string
	tx     orm.Query
}

func NewStore(issuer string) Store { return &databaseStore{issuer: issuer} }
func (r *databaseStore) query(ctx context.Context, table string) orm.Query {
	if r.tx != nil {
		return r.tx.Table(table).Where("issuer", r.issuer)
	}
	return facades.Orm().WithContext(ctx).Query().Table(table).Where("issuer", r.issuer)
}
func (r *databaseStore) Transaction(ctx context.Context, fn func(Store) error) error {
	if r.tx != nil {
		return fn(r)
	}
	return facades.Orm().WithContext(ctx).Transaction(func(tx orm.Query) error { return fn(&databaseStore{issuer: r.issuer, tx: tx}) })
}
func find(q orm.Query, dest any) error {
	err := q.First(dest)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil
	}
	return err
}
func (r *databaseStore) Client(ctx context.Context, id string, lock bool) (*Client, error) {
	q := r.query(ctx, clientsTable).Where("id", id)
	if lock {
		q = q.LockForUpdate()
	}
	var v Client
	err := find(q, &v)
	if err != nil || v.ID == "" {
		return nil, err
	}
	return &v, nil
}
func (r *databaseStore) SaveClient(ctx context.Context, v *Client) error {
	v.Issuer = r.issuer
	return r.query(ctx, clientsTable).Save(v)
}
func (r *databaseStore) CreateClient(ctx context.Context, v *Client) error {
	v.Issuer = r.issuer
	return r.query(ctx, clientsTable).Create(v)
}
func (r *databaseStore) Request(ctx context.Context, id string, lock bool) (*authorization, error) {
	q := r.query(ctx, requestsTable).Where("id", id)
	if lock {
		q = q.LockForUpdate()
	}
	var v authorization
	err := find(q, &v)
	if err != nil || v.ID == "" {
		return nil, err
	}
	return &v, nil
}
func (r *databaseStore) RequestByCode(ctx context.Context, hash string) (*authorization, error) {
	var v authorization
	err := find(r.query(ctx, requestsTable).Where("code_hash", hash), &v)
	if err != nil || v.ID == "" {
		return nil, err
	}
	return &v, nil
}
func (r *databaseStore) SaveRequest(ctx context.Context, v *authorization) error {
	v.Issuer = r.issuer
	return r.query(ctx, requestsTable).Save(v)
}
func (r *databaseStore) Grant(ctx context.Context, id string, lock bool) (*Connection, error) {
	q := r.query(ctx, grantsTable).Where("id", id)
	if lock {
		q = q.LockForUpdate()
	}
	var v Connection
	err := find(q, &v)
	if err != nil || v.ID == "" {
		return nil, err
	}
	return &v, nil
}
func (r *databaseStore) SaveGrant(ctx context.Context, v *Connection) error {
	v.Issuer = r.issuer
	return r.query(ctx, grantsTable).Save(v)
}
func (r *databaseStore) Token(ctx context.Context, id string, lock bool) (*token, error) {
	q := r.query(ctx, tokensTable).Where("id", id)
	if lock {
		q = q.LockForUpdate()
	}
	var v token
	err := find(q, &v)
	if err != nil || v.ID == "" {
		return nil, err
	}
	return &v, nil
}
func (r *databaseStore) Refresh(ctx context.Context, hash string, lock bool) (*token, error) {
	q := r.query(ctx, tokensTable).Where("kind", "refresh").Where("hash", hash)
	if lock {
		q = q.LockForUpdate()
	}
	var v token
	err := find(q, &v)
	if err != nil || v.ID == "" {
		return nil, err
	}
	return &v, nil
}
func (r *databaseStore) SaveToken(ctx context.Context, v *token) error {
	v.Issuer = r.issuer
	return r.query(ctx, tokensTable).Save(v)
}
func (r *databaseStore) Connections(ctx context.Context, user uuid.UUID) ([]Connection, error) {
	var result []Connection
	err := r.query(ctx, grantsTable).Where("user_id", user).WhereNull("revoked_at").Where("expires_at > ?", time.Now().UTC()).Order("created_at desc").Find(&result)
	return result, err
}
func (r *databaseStore) RevokeUser(ctx context.Context, user uuid.UUID, now time.Time) error {
	_, err := r.query(ctx, grantsTable).Where("user_id", user).WhereNull("revoked_at").Update("revoked_at", now)
	return err
}
func (r *databaseStore) Prune(ctx context.Context, before time.Time) error {
	// Keep spent credentials until their grant's absolute expiry plus retention;
	// deleting them at rotation would destroy replay detection.
	if _, err := r.query(ctx, tokensTable).Where("grant_id IN (SELECT id FROM "+grantsTable+" WHERE issuer = ? AND expires_at < ?)", r.issuer, before).Delete(&token{}); err != nil {
		return err
	}
	if _, err := r.query(ctx, requestsTable).Where("expires_at < ?", before).Where("grant_id = '' OR grant_id IN (SELECT id FROM "+grantsTable+" WHERE issuer = ? AND expires_at < ?)", r.issuer, before).Delete(&authorization{}); err != nil {
		return err
	}
	_, err := r.query(ctx, grantsTable).Where("expires_at < ?", before).Delete(&Connection{})
	return err
}
