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

// UserManagementTestSuite verifies the fail-closed authorization on the /users
// admin endpoints: they are gated behind the "admin" role (config default
// user_management_roles=["admin"]), so a non-admin user is rejected with 403
// while an admin succeeds.
type UserManagementTestSuite struct {
	suite.Suite
	tests.TestCase
	adminEmail  string
	memberEmail string
	password    string
}

func TestUserManagementTestSuite(t *testing.T) {
	suite.Run(t, new(UserManagementTestSuite))
}

func (s *UserManagementTestSuite) SetupTest() {
	s.password = "password123"
	s.adminEmail = "um-admin@test.local"
	s.memberEmail = "um-member@test.local"
	s.seedUser(s.adminEmail, "admin")
	s.seedUser(s.memberEmail, "user")
}

func (s *UserManagementTestSuite) TearDownTest() {
	for _, e := range []string{s.adminEmail, s.memberEmail} {
		_, _ = facades.Orm().Query().Where("email", e).Delete(&authmodels.User{})
	}
}

func (s *UserManagementTestSuite) seedUser(email, role string) {
	_, _ = facades.Orm().Query().Where("email", email).Delete(&authmodels.User{})
	hash, err := facades.Hash().Make(s.password)
	s.Require().NoError(err)
	s.Require().NoError(facades.Orm().Query().Create(&authmodels.User{
		ID:                uuid.New(),
		Email:             email,
		PasswordHash:      &hash,
		Role:              role,
		PasswordChangedAt: time.Now().UTC(),
	}))
}

func (s *UserManagementTestSuite) login(email string) *http.Cookie {
	t := s.T()
	body := `{"email":"` + email + `","password":"` + s.password + `"}`
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
	s.Require().NotNil(cookie, "no session cookie")
	return cookie
}

// A non-admin (role "user") is forbidden from every /users endpoint.
func (s *UserManagementTestSuite) TestNonAdminForbiddenFromUsers() {
	t := s.T()
	cookie := s.login(s.memberEmail)

	listResp, err := s.Http(t).WithCookie(cookie).Get("/api/v1/auth/users")
	s.Require().NoError(err)
	listResp.AssertStatus(http.StatusForbidden)

	createBody := `{"email":"nope@test.local","password":"password123","role":"user"}`
	createResp, err := s.Http(t).WithCookie(cookie).WithHeader("Content-Type", "application/json").
		Post("/api/v1/auth/users", bytes.NewBufferString(createBody))
	s.Require().NoError(err)
	createResp.AssertStatus(http.StatusForbidden)
}

// An admin can list users.
func (s *UserManagementTestSuite) TestAdminCanListUsers() {
	t := s.T()
	cookie := s.login(s.adminEmail)

	resp, err := s.Http(t).WithCookie(cookie).Get("/api/v1/auth/users")
	s.Require().NoError(err)
	resp.AssertStatus(http.StatusOK)
}

// A user created without an explicit role must NOT become an admin.
func (s *UserManagementTestSuite) TestCreatedUserDefaultsToNonAdmin() {
	t := s.T()
	cookie := s.login(s.adminEmail)
	newEmail := "um-created@test.local"
	_, _ = facades.Orm().Query().Where("email", newEmail).Delete(&authmodels.User{})
	defer func() { _, _ = facades.Orm().Query().Where("email", newEmail).Delete(&authmodels.User{}) }()

	body := `{"email":"` + newEmail + `","password":"password123"}`
	resp, err := s.Http(t).WithCookie(cookie).WithHeader("Content-Type", "application/json").
		Post("/api/v1/auth/users", bytes.NewBufferString(body))
	s.Require().NoError(err)
	resp.AssertStatus(http.StatusCreated)

	var created authmodels.User
	s.Require().NoError(facades.Orm().Query().Where("email", newEmail).First(&created))
	s.NotEqual("admin", created.Role, "a role-less create must never mint an admin")
	s.Equal("user", created.Role)
}
