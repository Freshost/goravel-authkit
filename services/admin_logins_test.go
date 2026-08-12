package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/freshost/goravel-authkit/repositories"
)

type fakeLoginEventsRepo struct {
	rows    []repositories.LoginEventRecord
	total   int64
	err     error
	actions []string
	page    int
	perPage int
}

func (f *fakeLoginEventsRepo) List(_ context.Context, actions []string, page, perPage int) ([]repositories.LoginEventRecord, int64, error) {
	f.actions = actions
	f.page = page
	f.perPage = perPage
	return f.rows, f.total, f.err
}

func TestAdminLoginsListDefaultsAndMapsRows(t *testing.T) {
	name := "Jane Doe"
	id := uuid.New()
	repo := &fakeLoginEventsRepo{
		rows: []repositories.LoginEventRecord{{
			ID: uuid.New(), UserID: &id, UserName: &name, UserEmail: "jane@example.com",
			Action: "auth.login", IP: "203.0.113.10", CreatedAt: time.Now().UTC(),
		}},
		total: 21,
	}

	page, err := NewAdminLogins(repo).List(context.Background(), AdminLoginQuery{})
	require.NoError(t, err)
	require.Equal(t, 1, repo.page)
	require.Equal(t, 20, repo.perPage)
	require.Equal(t, LoginActions, repo.actions)
	require.Equal(t, 2, page.TotalPages)
	require.Equal(t, name, page.Items[0].UserName)
	require.Equal(t, "jane@example.com", page.Items[0].UserEmail)
}

func TestAdminLoginsListValidatesPagination(t *testing.T) {
	service := NewAdminLogins(&fakeLoginEventsRepo{})

	_, err := service.List(context.Background(), AdminLoginQuery{Page: -1, PerPage: 20})
	require.ErrorIs(t, err, ErrValidation)

	_, err = service.List(context.Background(), AdminLoginQuery{Page: 1, PerPage: 101})
	require.ErrorIs(t, err, ErrValidation)
}

func TestAdminLoginsListWrapsRepositoryFailure(t *testing.T) {
	_, err := NewAdminLogins(&fakeLoginEventsRepo{err: errBoom}).List(context.Background(), AdminLoginQuery{})
	require.Error(t, err)
	require.True(t, errors.Is(err, errBoom))
}
