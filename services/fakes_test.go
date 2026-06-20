package services

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/freshost/goravel-authkit/models"
)

var errBoom = errors.New("boom")

// fakeRepo is an in-memory UsersRepository for service unit tests.
type fakeRepo struct {
	byID    map[uuid.UUID]*models.User
	byEmail map[string]*models.User
	failOp  bool // when true, every method returns errBoom
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{byID: map[uuid.UUID]*models.User{}, byEmail: map[string]*models.User{}}
}

func (f *fakeRepo) seed(u *models.User) {
	cp := *u
	f.byID[u.ID] = &cp
	f.byEmail[u.Email] = &cp
}

func (f *fakeRepo) FindByEmail(_ context.Context, email string) (*models.User, error) {
	if f.failOp {
		return nil, errBoom
	}
	if u, ok := f.byEmail[email]; ok {
		cp := *u
		return &cp, nil
	}
	return nil, nil
}

func (f *fakeRepo) FindByID(_ context.Context, id uuid.UUID) (*models.User, error) {
	if f.failOp {
		return nil, errBoom
	}
	if u, ok := f.byID[id]; ok {
		cp := *u
		return &cp, nil
	}
	return nil, nil
}

func (f *fakeRepo) List(_ context.Context) ([]models.User, error) {
	out := make([]models.User, 0, len(f.byID))
	for _, u := range f.byID {
		out = append(out, *u)
	}
	return out, nil
}

func (f *fakeRepo) Count(_ context.Context) (int64, error) { return int64(len(f.byID)), nil }

func (f *fakeRepo) Create(_ context.Context, u *models.User) error {
	f.seed(u)
	return nil
}

func (f *fakeRepo) Save(_ context.Context, u *models.User) error {
	// Re-key by email in case it changed.
	for e, existing := range f.byEmail {
		if existing.ID == u.ID {
			delete(f.byEmail, e)
		}
	}
	f.seed(u)
	return nil
}

func (f *fakeRepo) Delete(_ context.Context, u *models.User) error {
	delete(f.byID, u.ID)
	delete(f.byEmail, u.Email)
	return nil
}

func (f *fakeRepo) UpdatePassword(_ context.Context, id uuid.UUID, hash string, changedAt time.Time) error {
	if u, ok := f.byID[id]; ok {
		u.PasswordHash = &hash
		u.PasswordChangedAt = changedAt
	}
	return nil
}

// fakeHasher treats "hash:"+value as the hash; no crypto, fully deterministic.
type fakeHasher struct{}

func (fakeHasher) Make(value string) (string, error) { return "hash:" + value, nil }
func (fakeHasher) Check(value, hashed string) bool   { return "hash:"+value == hashed }

func ptr(s string) *string { return &s }
