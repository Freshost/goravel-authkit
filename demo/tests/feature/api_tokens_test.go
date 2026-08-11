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

type APITokensTestSuite struct {
	suite.Suite
	tests.TestCase
	userID   uuid.UUID
	email    string
	password string
}

func TestAPITokensTestSuite(t *testing.T) { suite.Run(t, new(APITokensTestSuite)) }

func (s *APITokensTestSuite) SetupTest() {
	s.userID = uuid.New()
	s.email = "api-token-" + uuid.NewString() + "@test.local"
	s.password = "password123"
	hash, err := facades.Hash().Make(s.password)
	s.Require().NoError(err)
	s.Require().NoError(facades.Orm().Query().Table("client_users").Create(&authmodels.User{
		ID: s.userID, Email: s.email, PasswordHash: &hash, Role: "user", PasswordChangedAt: time.Now().UTC(),
	}))
}

func (s *APITokensTestSuite) TearDownTest() {
	_, _ = facades.Orm().Query().Table("client_api_tokens").Where("user_id", s.userID).Delete(&authmodels.APIToken{})
	_, _ = facades.Orm().Query().Table("client_users").Where("id", s.userID).Delete(&authmodels.User{})
}

func (s *APITokensTestSuite) login() *http.Cookie {
	body := `{"email":"` + s.email + `","password":"` + s.password + `"}`
	resp, err := s.Http(s.T()).WithHeader("Content-Type", "application/json").Post("/api/client/v1/auth/login", bytes.NewBufferString(body))
	s.Require().NoError(err)
	resp.AssertOk()
	return cookieNamed(resp, "authkit_demo_session")
}

func (s *APITokensTestSuite) issue(cookie *http.Cookie) string {
	expiresAt := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	body := `{"name":"CI","expiresAt":"` + expiresAt + `","scopes":["profile:read"],"password":"` + s.password + `"}`
	resp, err := s.Http(s.T()).WithCookie(cookie).WithHeader("Content-Type", "application/json").Post("/api/client/v1/auth/api-tokens", bytes.NewBufferString(body))
	s.Require().NoError(err)
	resp.AssertStatus(http.StatusCreated)
	json, err := resp.Json()
	s.Require().NoError(err)
	plaintext, ok := json["token"].(string)
	s.Require().True(ok)
	s.Require().NotEmpty(plaintext)
	return plaintext
}

func (s *APITokensTestSuite) TestIssueAuthenticateScopesAndRevoke() {
	cookie := s.login()
	plaintext := s.issue(cookie)

	resp, err := s.Http(s.T()).WithHeader("Authorization", "Bearer "+plaintext).Get("/api/client/v1/token/whoami")
	s.Require().NoError(err)
	resp.AssertOk()
	json, err := resp.Json()
	s.Require().NoError(err)
	s.Equal(s.userID.String(), json["userId"])
	s.Equal("api_token", json["authMethod"])
	s.Equal(true, json["canRead"])

	insufficient, err := s.Http(s.T()).WithHeader("Authorization", "Bearer "+plaintext).Get("/api/client/v1/token-write/whoami")
	s.Require().NoError(err)
	insufficient.AssertStatus(http.StatusForbidden)

	list, err := s.Http(s.T()).WithCookie(cookie).Get("/api/client/v1/auth/api-tokens")
	s.Require().NoError(err)
	list.AssertOk()
	list.AssertSee([]string{"CI", "profile:read"})
	list.AssertDontSee([]string{plaintext})

	revoke, err := s.Http(s.T()).WithCookie(cookie).Delete("/api/client/v1/auth/api-tokens", nil)
	s.Require().NoError(err)
	revoke.AssertOk()

	rejected, err := s.Http(s.T()).WithHeader("Authorization", "Bearer "+plaintext).Get("/api/client/v1/token/whoami")
	s.Require().NoError(err)
	rejected.AssertUnauthorized()
}

func (s *APITokensTestSuite) TestHybridSessionAndInvalidBearerPrecedence() {
	cookie := s.login()

	session, err := s.Http(s.T()).WithCookie(cookie).Get("/api/client/v1/either/whoami")
	s.Require().NoError(err)
	session.AssertOk()
	json, err := session.Json()
	s.Require().NoError(err)
	s.Equal("session", json["authMethod"])

	invalid, err := s.Http(s.T()).WithCookie(cookie).WithHeader("Authorization", "Bearer invalid").Get("/api/client/v1/either/whoami")
	s.Require().NoError(err)
	invalid.AssertUnauthorized()
}

func (s *APITokensTestSuite) TestPasswordChangeRevokesTokens() {
	cookie := s.login()
	plaintext := s.issue(cookie)
	body := `{"currentPassword":"` + s.password + `","newPassword":"newpassword456"}`

	changed, err := s.Http(s.T()).WithCookie(cookie).WithHeader("Content-Type", "application/json").Put("/api/client/v1/auth/password", bytes.NewBufferString(body))
	s.Require().NoError(err)
	changed.AssertOk()

	rejected, err := s.Http(s.T()).WithHeader("Authorization", "Bearer "+plaintext).Get("/api/client/v1/token/whoami")
	s.Require().NoError(err)
	rejected.AssertUnauthorized()
}
