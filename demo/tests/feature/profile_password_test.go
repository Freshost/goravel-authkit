package feature

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/goravel/framework/facades"
	"github.com/stretchr/testify/suite"

	authmodels "github.com/freshost/goravel-authkit/models"

	"goravel/tests"
)

// ProfilePasswordTestSuite covers the self-service profile (PUT /me) and the
// new-password validation branches of change-password (PUT /password) that are
// not already covered by change_password_test.go (which guards the
// session-survival behaviour). Two users are seeded so the duplicate-email
// collision can be exercised.
type ProfilePasswordTestSuite struct {
	suite.Suite
	tests.TestCase
	email    string
	other    string
	password string
}

func TestProfilePasswordTestSuite(t *testing.T) {
	suite.Run(t, new(ProfilePasswordTestSuite))
}

func (s *ProfilePasswordTestSuite) SetupTest() {
	s.password = "password123"
	suffix := uuid.NewString()
	s.email = "profile-" + suffix + "@test.local"
	s.other = "profile-other-" + suffix + "@test.local"
	s.seed(s.email)
	s.seed(s.other)
}

func (s *ProfilePasswordTestSuite) TearDownTest() {
	for _, e := range []string{s.email, s.other} {
		_, _ = facades.Orm().Query().Where("email", e).Delete(&authmodels.User{})
	}
}

func (s *ProfilePasswordTestSuite) seed(email string) {
	hash, err := facades.Hash().Make(s.password)
	s.Require().NoError(err)
	s.Require().NoError(facades.Orm().Query().Create(&authmodels.User{
		ID:                uuid.New(),
		Email:             email,
		PasswordHash:      &hash,
		Role:              "user",
		PasswordChangedAt: time.Now().UTC(),
	}))
}

func (s *ProfilePasswordTestSuite) login() *http.Cookie {
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

// PUT /me updates the caller's own name and email.
func (s *ProfilePasswordTestSuite) TestUpdateProfile() {
	t := s.T()
	c := s.login()
	newEmail := "profile-renamed-" + uuid.NewString() + "@test.local"
	defer func() { _, _ = facades.Orm().Query().Where("email", newEmail).Delete(&authmodels.User{}) }()

	body := `{"email":"` + newEmail + `","name":"Renamed Person"}`
	resp, err := s.Http(t).WithCookie(c).WithHeader("Content-Type", "application/json").
		Put("/api/v1/auth/me", bytes.NewBufferString(body))
	s.Require().NoError(err)
	resp.AssertStatus(http.StatusOK)
	json, err := resp.Json()
	s.Require().NoError(err)
	s.Equal(newEmail, json["email"])
	s.Equal("Renamed Person", json["name"])
}

// Changing your email to one already taken by another user returns 409.
func (s *ProfilePasswordTestSuite) TestUpdateProfileDuplicateEmail() {
	t := s.T()
	c := s.login()
	body := `{"email":"` + s.other + `","name":"Collide"}`
	resp, err := s.Http(t).WithCookie(c).WithHeader("Content-Type", "application/json").
		Put("/api/v1/auth/me", bytes.NewBufferString(body))
	s.Require().NoError(err)
	resp.AssertStatus(http.StatusConflict)
	json, err := resp.Json()
	s.Require().NoError(err)
	s.Equal("already_exists", json["error"])
}

// change-password rejects a too-short new password (min length is 8).
func (s *ProfilePasswordTestSuite) TestChangePasswordTooShort() {
	t := s.T()
	c := s.login()
	body := `{"currentPassword":"` + s.password + `","newPassword":"short"}`
	resp, err := s.Http(t).WithCookie(c).WithHeader("Content-Type", "application/json").
		Put("/api/v1/auth/password", bytes.NewBufferString(body))
	s.Require().NoError(err)
	resp.AssertStatus(http.StatusBadRequest)
	json, err := resp.Json()
	s.Require().NoError(err)
	s.Equal("validation_error", json["error"])
}

// change-password rejects an all-whitespace new password.
func (s *ProfilePasswordTestSuite) TestChangePasswordAllWhitespace() {
	t := s.T()
	c := s.login()
	body := `{"currentPassword":"` + s.password + `","newPassword":"          "}`
	resp, err := s.Http(t).WithCookie(c).WithHeader("Content-Type", "application/json").
		Put("/api/v1/auth/password", bytes.NewBufferString(body))
	s.Require().NoError(err)
	resp.AssertStatus(http.StatusBadRequest)
	json, err := resp.Json()
	s.Require().NoError(err)
	s.Equal("validation_error", json["error"])
}

// change-password rejects a new password longer than bcrypt's 72-byte limit.
func (s *ProfilePasswordTestSuite) TestChangePasswordTooLong() {
	t := s.T()
	c := s.login()
	long := strings.Repeat("a", 73)
	body := `{"currentPassword":"` + s.password + `","newPassword":"` + long + `"}`
	resp, err := s.Http(t).WithCookie(c).WithHeader("Content-Type", "application/json").
		Put("/api/v1/auth/password", bytes.NewBufferString(body))
	s.Require().NoError(err)
	resp.AssertStatus(http.StatusBadRequest)
	json, err := resp.Json()
	s.Require().NoError(err)
	s.Equal("validation_error", json["error"])
}

// change-password with the wrong current password is rejected (wrong_password).
func (s *ProfilePasswordTestSuite) TestChangePasswordWrongCurrent() {
	t := s.T()
	c := s.login()
	body := `{"currentPassword":"not-the-password","newPassword":"newpassword456"}`
	resp, err := s.Http(t).WithCookie(c).WithHeader("Content-Type", "application/json").
		Put("/api/v1/auth/password", bytes.NewBufferString(body))
	s.Require().NoError(err)
	resp.AssertStatus(http.StatusBadRequest)
	json, err := resp.Json()
	s.Require().NoError(err)
	s.Equal("wrong_password", json["error"])
}
