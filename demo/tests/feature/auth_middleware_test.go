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

// AuthMiddlewareTestSuite exercises the Authenticated middleware end-to-end:
// a correct login establishes a session that reaches the guarded /me, while
// wrong password, unknown email, and a cookie-less request are all rejected.
// Wrong-password and unknown-email must return the SAME generic
// invalid-credentials envelope (no user enumeration).
type AuthMiddlewareTestSuite struct {
	suite.Suite
	tests.TestCase
	email    string
	password string
}

func TestAuthMiddlewareTestSuite(t *testing.T) {
	suite.Run(t, new(AuthMiddlewareTestSuite))
}

func (s *AuthMiddlewareTestSuite) SetupTest() {
	s.email = "authmw-" + uuid.NewString() + "@test.local"
	s.password = "password123"
	hash, err := facades.Hash().Make(s.password)
	s.Require().NoError(err)
	s.Require().NoError(facades.Orm().Query().Create(&authmodels.User{
		ID:                uuid.New(),
		Email:             s.email,
		PasswordHash:      &hash,
		Role:              "user",
		PasswordChangedAt: time.Now().UTC(),
	}))
}

func (s *AuthMiddlewareTestSuite) TearDownTest() {
	_, _ = facades.Orm().Query().Where("email", s.email).Delete(&authmodels.User{})
}

func (s *AuthMiddlewareTestSuite) sessionCookie(resp interface {
	Cookies() []*http.Cookie
}) *http.Cookie {
	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "authkit_demo_session" {
			cookie = c
		}
	}
	return cookie
}

// A correct login returns 200, sets a session cookie, and that cookie reaches
// the guarded /me endpoint.
func (s *AuthMiddlewareTestSuite) TestLoginSuccessThenMe() {
	t := s.T()
	body := `{"email":"` + s.email + `","password":"` + s.password + `"}`
	resp, err := s.Http(t).WithHeader("Content-Type", "application/json").
		Post("/api/v1/auth/login", bytes.NewBufferString(body))
	s.Require().NoError(err)
	resp.AssertStatus(http.StatusOK)

	cookie := s.sessionCookie(resp)
	s.Require().NotNil(cookie, "login must set a session cookie")

	me, err := s.Http(t).WithCookie(cookie).Get("/api/v1/auth/me")
	s.Require().NoError(err)
	me.AssertStatus(http.StatusOK)
	json, err := me.Json()
	s.Require().NoError(err)
	s.Equal(s.email, json["email"])
}

// A wrong password is rejected with 401 and the generic invalid-credentials code.
func (s *AuthMiddlewareTestSuite) TestWrongPassword() {
	t := s.T()
	body := `{"email":"` + s.email + `","password":"wrong-password"}`
	resp, err := s.Http(t).WithHeader("Content-Type", "application/json").
		Post("/api/v1/auth/login", bytes.NewBufferString(body))
	s.Require().NoError(err)
	resp.AssertStatus(http.StatusUnauthorized)
	json, err := resp.Json()
	s.Require().NoError(err)
	s.Equal("invalid_credentials", json["error"])
}

// An unknown email is rejected with the SAME 401 + generic message as a wrong
// password — no user enumeration.
func (s *AuthMiddlewareTestSuite) TestUnknownEmailNoEnumeration() {
	t := s.T()
	body := `{"email":"definitely-not-a-user-` + uuid.NewString() + `@test.local","password":"password123"}`
	resp, err := s.Http(t).WithHeader("Content-Type", "application/json").
		Post("/api/v1/auth/login", bytes.NewBufferString(body))
	s.Require().NoError(err)
	resp.AssertStatus(http.StatusUnauthorized)
	json, err := resp.Json()
	s.Require().NoError(err)
	s.Equal("invalid_credentials", json["error"], "unknown email must reuse the wrong-password code")
	s.Equal("Invalid email or password", json["message"])
}

// A guarded request with no session cookie is rejected with 401.
func (s *AuthMiddlewareTestSuite) TestMeWithoutCookie() {
	t := s.T()
	resp, err := s.Http(t).Get("/api/v1/auth/me")
	s.Require().NoError(err)
	resp.AssertStatus(http.StatusUnauthorized)
}
