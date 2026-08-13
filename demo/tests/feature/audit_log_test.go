package feature

import (
	"bytes"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/goravel/framework/facades"
	"github.com/stretchr/testify/suite"

	authmodels "github.com/freshost/goravel-authkit/models"

	"goravel/tests"
)

// AuditLogTestSuite verifies that a successful login leaves a forensic trail:
// an "auth.login" row is written to the audit_logs table, scoped to the
// authenticating user. It asserts the persisted row directly through the ORM
// (filtered by this test's unique actor id) rather than relying solely on the
// login-history endpoint.
type AuditLogTestSuite struct {
	suite.Suite
	tests.TestCase
	email    string
	password string
	userID   uuid.UUID
}

func TestAuditLogTestSuite(t *testing.T) {
	suite.Run(t, new(AuditLogTestSuite))
}

func (s *AuditLogTestSuite) SetupTest() {
	s.email = "audit-" + uuid.NewString() + "@test.local"
	s.password = "password123"
	s.userID = uuid.New()
	name := "Audit Administrator"
	hash, err := facades.Hash().Make(s.password)
	s.Require().NoError(err)
	s.Require().NoError(facades.Orm().Query().Create(&authmodels.User{
		ID:                s.userID,
		Name:              &name,
		Email:             s.email,
		PasswordHash:      &hash,
		Role:              "admin",
		PasswordChangedAt: time.Now().UTC(),
	}))
}

func (s *AuditLogTestSuite) createUser(email, password, name, role string) uuid.UUID {
	id := uuid.New()
	hash, err := facades.Hash().Make(password)
	s.Require().NoError(err)
	s.Require().NoError(facades.Orm().Query().Create(&authmodels.User{
		ID: id, Name: &name, Email: email, PasswordHash: &hash, Role: role,
		PasswordChangedAt: time.Now().UTC(),
	}))
	s.T().Cleanup(func() {
		_, _ = facades.Orm().Query().Where("actor_id", id).Delete(&authmodels.AuditLog{})
		_, _ = facades.Orm().Query().Where("id", id).Delete(&authmodels.User{})
	})
	return id
}

func (s *AuditLogTestSuite) loginAs(email, password string) *http.Cookie {
	body := `{"email":"` + email + `","password":"` + password + `"}`
	resp, err := s.Http(s.T()).WithHeader("Content-Type", "application/json").
		Post("/api/v1/auth/login", bytes.NewBufferString(body))
	s.Require().NoError(err)
	resp.AssertStatus(http.StatusOK)
	for _, c := range resp.Cookies() {
		if c.Name == "authkit_demo_session" {
			return c
		}
	}
	s.FailNow("login did not return the Authkit session cookie")
	return nil
}

func (s *AuditLogTestSuite) TearDownTest() {
	// Clean up the audit rows this test produced, then the user.
	_, _ = facades.Orm().Query().Where("actor_id", s.userID).Delete(&authmodels.AuditLog{})
	_, _ = facades.Orm().Query().Where("email", s.email).Delete(&authmodels.User{})
}

func (s *AuditLogTestSuite) login() *http.Cookie {
	return s.loginAs(s.email, s.password)
}

func (s *AuditLogTestSuite) TestAdminCanListAllSuccessfulLogins() {
	adminCookie := s.login()
	memberEmail := "member-" + uuid.NewString() + "@test.local"
	memberName := "Audit Member"
	memberID := s.createUser(memberEmail, "password123", memberName, "user")
	s.Require().NotNil(s.loginAs(memberEmail, "password123"))
	s.Require().NotNil(s.loginAs(memberEmail, "password123"))

	resp, err := s.Http(s.T()).WithCookie(adminCookie).
		Get("/api/v1/auth/admin/logins?page=1&perPage=20")
	s.Require().NoError(err)
	resp.AssertStatus(http.StatusOK)

	var page struct {
		Items []struct {
			UserID    *string `json:"userId"`
			UserName  string  `json:"userName"`
			UserEmail string  `json:"userEmail"`
			Action    string  `json:"action"`
			IP        string  `json:"ip"`
			CreatedAt string  `json:"createdAt"`
		} `json:"items"`
		Page       int   `json:"page"`
		PerPage    int   `json:"perPage"`
		Total      int64 `json:"total"`
		TotalPages int   `json:"totalPages"`
	}
	s.Require().NoError(resp.Bind(&page))
	s.Equal(1, page.Page)
	s.Equal(20, page.PerPage)
	s.GreaterOrEqual(page.Total, int64(2))
	s.GreaterOrEqual(page.TotalPages, 1)

	found := false
	memberIP := ""
	for _, item := range page.Items {
		if item.UserID != nil && *item.UserID == memberID.String() {
			found = true
			memberIP = item.IP
			s.Equal(memberName, item.UserName)
			s.Equal(memberEmail, item.UserEmail)
			s.Equal("auth.login", item.Action)
			s.NotEmpty(item.IP)
			s.NotEmpty(item.CreatedAt)
		}
	}
	s.True(found, "administrator login overview should contain the member sign-in")

	filteredResp, err := s.Http(s.T()).WithCookie(adminCookie).Get(
		"/api/v1/auth/admin/logins?page=1&perPage=20&sort=asc&method=password&user=" +
			url.QueryEscape(memberEmail) + "&ip=" + url.QueryEscape(memberIP),
	)
	s.Require().NoError(err)
	filteredResp.AssertStatus(http.StatusOK)

	var filteredPage struct {
		Items []struct {
			UserID    *string `json:"userId"`
			UserEmail string  `json:"userEmail"`
			Action    string  `json:"action"`
			IP        string  `json:"ip"`
			CreatedAt string  `json:"createdAt"`
		} `json:"items"`
		Total int64 `json:"total"`
	}
	s.Require().NoError(filteredResp.Bind(&filteredPage))
	s.Equal(int64(2), filteredPage.Total)
	s.Require().Len(filteredPage.Items, 2)
	for _, item := range filteredPage.Items {
		s.Require().NotNil(item.UserID)
		s.Equal(memberID.String(), *item.UserID)
		s.Equal(memberEmail, item.UserEmail)
		s.Equal("auth.login", item.Action)
		s.Equal(memberIP, item.IP)
	}
	first, err := time.Parse(time.RFC3339Nano, filteredPage.Items[0].CreatedAt)
	s.Require().NoError(err)
	second, err := time.Parse(time.RFC3339Nano, filteredPage.Items[1].CreatedAt)
	s.Require().NoError(err)
	s.False(second.Before(first), "ascending sort should return the oldest sign-in first")
}

func (s *AuditLogTestSuite) TestAdminLoginFiltersRejectUnknownValues() {
	adminCookie := s.login()
	resp, err := s.Http(s.T()).WithCookie(adminCookie).
		Get("/api/v1/auth/admin/logins?method=magic-link&sort=sideways")
	s.Require().NoError(err)
	resp.AssertStatus(http.StatusBadRequest)
}

func (s *AuditLogTestSuite) TestNonAdminCannotListAllLogins() {
	memberEmail := "member-" + uuid.NewString() + "@test.local"
	s.createUser(memberEmail, "password123", "Audit Member", "user")
	memberCookie := s.loginAs(memberEmail, "password123")

	resp, err := s.Http(s.T()).WithCookie(memberCookie).Get("/api/v1/auth/admin/logins")
	s.Require().NoError(err)
	resp.AssertStatus(http.StatusForbidden)
}

// A successful login writes an "auth.login" audit row for the authenticating
// user, and an "auth.login" entry surfaces through GET /auth/logins.
func (s *AuditLogTestSuite) TestSuccessfulLoginWritesAuditEntry() {
	t := s.T()
	cookie := s.login()

	// Direct table assertion: exactly the login row for this unique user.
	var rows []authmodels.AuditLog
	s.Require().NoError(facades.Orm().Query().
		Where("actor_id", s.userID).
		Where("action", "auth.login").
		Find(&rows))
	s.Require().NotEmpty(rows, "a successful login must write an auth.login audit row")
	s.Equal("user", rows[0].ResourceType)
	s.Require().NotNil(rows[0].ResourceID)
	s.Equal(s.userID.String(), *rows[0].ResourceID)

	// And the login-history endpoint surfaces it.
	hist, err := s.Http(t).WithCookie(cookie).Get("/api/v1/auth/logins")
	s.Require().NoError(err)
	hist.AssertStatus(http.StatusOK)
	var entries []map[string]any
	s.Require().NoError(hist.Bind(&entries))
	s.Require().NotEmpty(entries)
	s.Equal("auth.login", entries[0]["action"])
}
