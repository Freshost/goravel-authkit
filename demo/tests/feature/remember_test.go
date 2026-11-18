package feature

import (
	"bytes"
	"context"
	"github.com/freshost/goravel-authkit/repositories"
	"github.com/freshost/goravel-authkit/services"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/goravel/framework/facades"
	"github.com/stretchr/testify/suite"

	authmodels "github.com/freshost/goravel-authkit/models"

	"goravel/tests"
)

// RememberTestSuite exercises the RememberLogin middleware end-to-end against the
// real routes: a remember cookie must silently re-establish a session when none
// exists, rotate on use, be rejected when invalid, and be refused for a disabled
// account.
type RememberTestSuite struct {
	suite.Suite
	tests.TestCase
	email    string
	password string
}

func TestRememberTestSuite(t *testing.T) {
	suite.Run(t, new(RememberTestSuite))
}

func (s *RememberTestSuite) SetupTest() {
	s.email = "remember-it@test.local"
	s.password = "password123"
	// Idempotent seed of a known user.
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

func (s *RememberTestSuite) TearDownTest() {
	_, _ = facades.Orm().Query().Where("email", s.email).Delete(&authmodels.User{})
}

// loginRemember logs in with remember=true and returns the issued remember cookie.
func (s *RememberTestSuite) loginRemember() *http.Cookie {
	t := s.T()
	body := `{"email":"` + s.email + `","password":"` + s.password + `","remember":true}`
	resp, err := s.Http(t).WithHeader("Content-Type", "application/json").
		Post("/api/v1/auth/login", bytes.NewBufferString(body))
	s.Require().NoError(err)
	resp.AssertStatus(http.StatusOK)
	cookie := resp.Cookie("authkit_remember")
	s.Require().NotNil(cookie, "login with remember=true must set the remember cookie")
	return cookie
}

func (s *RememberTestSuite) TestAutoLoginFromRememberCookie() {
	t := s.T()
	remember := s.loginRemember()

	// A request carrying ONLY the remember cookie (no session) is auto-logged-in.
	resp, err := s.Http(t).WithCookie(remember).Get("/api/v1/auth/me")
	s.Require().NoError(err)
	resp.AssertStatus(http.StatusOK)
	json, err := resp.Json()
	s.Require().NoError(err)
	s.Equal(s.email, json["email"])
	// The validator is rotated, so a fresh remember cookie is issued.
	s.NotNil(resp.Cookie("authkit_remember"), "remember cookie should be rotated")
}

func (s *RememberTestSuite) TestInvalidRememberCookieRejected() {
	t := s.T()
	bad := &http.Cookie{Name: "authkit_remember", Value: "bogus:bogus"}
	resp, err := s.Http(t).WithCookie(bad).Get("/api/v1/auth/me")
	s.Require().NoError(err)
	resp.AssertStatus(http.StatusUnauthorized)
}

func (s *RememberTestSuite) TestDisabledAccountRememberRefused() {
	t := s.T()
	remember := s.loginRemember()

	// Lock the account after the cookie was issued.
	_, err := facades.Orm().Query().Model(&authmodels.User{}).
		Where("email", s.email).Update("disabled_at", time.Now().UTC())
	s.Require().NoError(err)

	resp, err := s.Http(t).WithCookie(remember).Get("/api/v1/auth/me")
	s.Require().NoError(err)
	resp.AssertStatus(http.StatusUnauthorized)
}

func (s *RememberTestSuite) TestPasswordEpochInvalidatesRememberCookieWithoutCleanup() {
	t := s.T()
	remember := s.loginRemember()

	// Simulate the atomic part of an admin password reset. Even if deleting the
	// remember row later fails, the credential epoch alone must reject the cookie.
	_, err := facades.Orm().Query().Model(&authmodels.User{}).
		Where("email", s.email).Update("password_changed_at", time.Now().Add(time.Second).UTC())
	s.Require().NoError(err)

	resp, err := s.Http(t).WithCookie(remember).Get("/api/v1/auth/me")
	s.Require().NoError(err)
	resp.AssertStatus(http.StatusUnauthorized)
}

func (s *RememberTestSuite) TestRemoteSignOutRevokesPersistentCredential() {
	remember := s.loginRemember()
	restored, err := s.Http(s.T()).WithCookie(remember).Get("/api/v1/auth/me")
	s.Require().NoError(err)
	restored.AssertOk()
	remember = restored.Cookie("authkit_remember")
	s.Require().NotNil(remember)
	var user authmodels.User
	s.Require().NoError(facades.Orm().Query().Where("email", s.email).First(&user))
	sessions := repositories.NewSessions()
	s.Require().NoError(sessions.DeleteByUser(context.Background(), user.ID))
	for i := 0; i < 2; i++ {
		denied, err := s.Http(s.T()).WithCookie(remember).Get("/api/v1/auth/me")
		s.Require().NoError(err)
		denied.AssertUnauthorized()
	}
}
func (s *RememberTestSuite) TestRememberCannotBorrowPasswordResetEpoch() {
	var verified authmodels.User
	s.Require().NoError(facades.Orm().Query().Where("email", s.email).First(&verified))
	repo := repositories.NewUsers()
	s.Require().NoError(repo.UpdatePassword(context.Background(), verified.ID, *verified.PasswordHash, time.Now()))
	remember := services.NewRemember(repositories.NewRemember(), time.Hour)
	// Issued after reset, using only the password proof captured before reset.
	value, err := remember.IssueVerified(context.Background(), verified.ID, verified.PasswordChangedAt, "late-proof-"+uuid.NewString())
	s.Require().NoError(err)
	response, err := s.Http(s.T()).WithCookie(&http.Cookie{Name: "authkit_remember", Value: value}).Get("/api/v1/auth/me")
	s.Require().NoError(err)
	response.AssertUnauthorized()
}
