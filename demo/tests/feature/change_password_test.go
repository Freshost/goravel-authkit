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

// ChangePasswordTestSuite is a regression guard for the timestamp-precision bug:
// a password change must keep the CALLER's session alive while logging out the
// others. (Postgres timestamptz is µs precision, so stamping a raw ns time would
// never match the DB value on the next request and would 401 the caller.)
type ChangePasswordTestSuite struct {
	suite.Suite
	tests.TestCase
	email    string
	password string
}

func TestChangePasswordTestSuite(t *testing.T) {
	suite.Run(t, new(ChangePasswordTestSuite))
}

func (s *ChangePasswordTestSuite) SetupTest() {
	s.email = "changepw-it@test.local"
	s.password = "password123"
	_, _ = facades.Orm().Query().Where("email", s.email).Delete(&authmodels.User{})
	hash, err := facades.Hash().Make(s.password)
	s.Require().NoError(err)
	s.Require().NoError(facades.Orm().Query().Create(&authmodels.User{
		ID:                uuid.New(),
		Email:             s.email,
		PasswordHash:      &hash,
		Role:              "admin",
		PasswordChangedAt: time.Now().UTC(),
	}))
}

func (s *ChangePasswordTestSuite) TearDownTest() {
	_, _ = facades.Orm().Query().Where("email", s.email).Delete(&authmodels.User{})
}

func (s *ChangePasswordTestSuite) login() *http.Cookie {
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

func (s *ChangePasswordTestSuite) TestChangerStaysInOthersOut() {
	t := s.T()
	a := s.login()
	b := s.login()

	// Change the password using session B.
	body := `{"currentPassword":"` + s.password + `","newPassword":"newpassword456"}`
	chg, err := s.Http(t).WithCookie(b).WithHeader("Content-Type", "application/json").
		Put("/api/v1/auth/password", bytes.NewBufferString(body))
	s.Require().NoError(err)
	chg.AssertStatus(http.StatusOK)

	// B (the changer) must stay signed in...
	bResp, err := s.Http(t).WithCookie(b).Get("/api/v1/auth/me")
	s.Require().NoError(err)
	bResp.AssertStatus(http.StatusOK)

	// ...while A (another session) is logged out.
	aResp, err := s.Http(t).WithCookie(a).Get("/api/v1/auth/me")
	s.Require().NoError(err)
	aResp.AssertStatus(http.StatusUnauthorized)
}
