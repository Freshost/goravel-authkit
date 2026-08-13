package services

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/freshost/goravel-authkit/repositories"
)

const (
	defaultAdminLoginPageSize = 20
	maxAdminLoginPageSize     = 100
	loginActionPassword       = "auth.login"
	loginActionRemember       = "auth.login_remember"
)

// AdminLoginQuery controls the bounded administrator sign-in listing.
type AdminLoginQuery struct {
	Page    int
	PerPage int
	User    string
	IP      string
	Method  string
	Sort    string
}

// AdminLoginEvent is one successful sign-in visible to an administrator.
type AdminLoginEvent struct {
	ID        uuid.UUID
	UserID    *uuid.UUID
	UserName  string
	UserEmail string
	Action    string
	IP        string
	CreatedAt time.Time
}

// AdminLoginPage is a stable page of sign-ins plus pagination metadata.
type AdminLoginPage struct {
	Items      []AdminLoginEvent
	Page       int
	PerPage    int
	Total      int64
	TotalPages int
}

// AdminLogins owns validation and orchestration for the administrator overview.
type AdminLogins struct {
	repo repositories.LoginEventsRepository
}

func NewAdminLogins(repo repositories.LoginEventsRepository) *AdminLogins {
	return &AdminLogins{repo: repo}
}

// List returns filtered successful password and remember-cookie sign-ins.
func (s *AdminLogins) List(ctx context.Context, query AdminLoginQuery) (*AdminLoginPage, error) {
	if query.Page == 0 {
		query.Page = 1
	}
	if query.PerPage == 0 {
		query.PerPage = defaultAdminLoginPageSize
	}
	if query.Page < 1 {
		return nil, fmt.Errorf("%w: page must be at least 1", ErrValidation)
	}
	if query.PerPage < 1 || query.PerPage > maxAdminLoginPageSize {
		return nil, fmt.Errorf("%w: perPage must be between 1 and %d", ErrValidation, maxAdminLoginPageSize)
	}
	query.User = strings.TrimSpace(query.User)
	query.IP = strings.TrimSpace(query.IP)
	query.Method = strings.ToLower(strings.TrimSpace(query.Method))
	query.Sort = strings.ToLower(strings.TrimSpace(query.Sort))
	if len(query.User) > 255 {
		return nil, fmt.Errorf("%w: user filter must be at most 255 characters", ErrValidation)
	}
	if len(query.IP) > 64 {
		return nil, fmt.Errorf("%w: IP filter must be at most 64 characters", ErrValidation)
	}

	methodAction := ""
	switch query.Method {
	case "":
	case "password":
		methodAction = loginActionPassword
	case "remember":
		methodAction = loginActionRemember
	default:
		return nil, fmt.Errorf("%w: method must be password or remember", ErrValidation)
	}
	oldestFirst := false
	switch query.Sort {
	case "", "desc":
	case "asc":
		oldestFirst = true
	default:
		return nil, fmt.Errorf("%w: sort must be asc or desc", ErrValidation)
	}

	rows, total, err := s.repo.List(ctx, repositories.LoginEventFilter{
		Actions:      LoginActions,
		User:         query.User,
		IP:           query.IP,
		MethodAction: methodAction,
		OldestFirst:  oldestFirst,
	}, query.Page, query.PerPage)
	if err != nil {
		return nil, fmt.Errorf("list administrator logins: %w", err)
	}

	items := make([]AdminLoginEvent, 0, len(rows))
	for _, row := range rows {
		name := ""
		if row.UserName != nil {
			name = *row.UserName
		}
		items = append(items, AdminLoginEvent{
			ID:        row.ID,
			UserID:    row.UserID,
			UserName:  name,
			UserEmail: row.UserEmail,
			Action:    row.Action,
			IP:        row.IP,
			CreatedAt: row.CreatedAt,
		})
	}

	totalPages := 0
	if total > 0 {
		totalPages = int((total + int64(query.PerPage) - 1) / int64(query.PerPage))
	}
	return &AdminLoginPage{
		Items: items, Page: query.Page, PerPage: query.PerPage,
		Total: total, TotalPages: totalPages,
	}, nil
}
