package feature

import (
	"bytes"
	"net/http"
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
	hash, err := facades.Hash().Make(s.password)
	s.Require().NoError(err)
	s.Require().NoError(facades.Orm().Query().Create(&authmodels.User{
		ID:                s.userID,
		Email:             s.email,
		PasswordHash:      &hash,
		Role:              "user",
		PasswordChangedAt: time.Now().UTC(),
	}))
}

func (s *AuditLogTestSuite) TearDownTest() {
	// Clean up the audit rows this test produced, then the user.
	_, _ = facades.Orm().Query().Where("actor_id", s.userID).Delete(&authmodels.AuditLog{})
	_, _ = facades.Orm().Query().Where("email", s.email).Delete(&authmodels.User{})
}

func (s *AuditLogTestSuite) login() *http.Cookie {
	t := s.T()
	body := `{"email":"` + s.email + `","password":"` + s.password + `"}`
	resp, err := s.Http(t).WithHeader("Content-Type", "application/json").
		Post("/api/v1/auth/login", bytes.NewBufferString(body))
	s.Require().NoError(err)
	resp.AssertStatus(http.StatusOK)
	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "authkit_demo_session" {
			cookie = c
		}
	}
	s.Require().NotNil(cookie)
	return cookie
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
