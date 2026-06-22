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

// SessionsTestSuite exercises the active-session endpoints and the TrackSession
// kill-switch against the real routes.
type SessionsTestSuite struct {
	suite.Suite
	tests.TestCase
	email    string
	password string
}

func TestSessionsTestSuite(t *testing.T) {
	suite.Run(t, new(SessionsTestSuite))
}

func (s *SessionsTestSuite) SetupTest() {
	s.email = "sessions-it@test.local"
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

func (s *SessionsTestSuite) TearDownTest() {
	_, _ = facades.Orm().Query().Where("email", s.email).Delete(&authmodels.User{})
}

// login returns the session cookie for a fresh login.
func (s *SessionsTestSuite) login(userAgent string) *http.Cookie {
	t := s.T()
	body := `{"email":"` + s.email + `","password":"` + s.password + `"}`
	resp, err := s.Http(t).WithHeader("Content-Type", "application/json").
		WithHeader("User-Agent", userAgent).
		Post("/api/v1/auth/login", bytes.NewBufferString(body))
	s.Require().NoError(err)
	resp.AssertStatus(http.StatusOK)
	// Login emits the session cookie twice (StartSession, then the regenerated
	// id). The authenticated session is the LAST one.
	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "authkit_demo_session" {
			cookie = c
		}
	}
	s.Require().NotNil(cookie)
	return cookie
}

func (s *SessionsTestSuite) TestListMarksCurrent() {
	t := s.T()
	c := s.login("Device-A/1.0")

	resp, err := s.Http(t).WithCookie(c).Get("/api/v1/auth/sessions")
	s.Require().NoError(err)
	resp.AssertStatus(http.StatusOK)
	content, err := resp.Content()
	s.Require().NoError(err)
	s.Contains(content, "\"current\":true")
	s.Contains(content, "Device-A/1.0")
}

func (s *SessionsTestSuite) TestTerminateOtherSessionKillSwitch() {
	t := s.T()
	a := s.login("Device-A/1.0")
	b := s.login("Device-B/2.0")

	// From A, find B's (non-current) session id.
	resp, err := s.Http(t).WithCookie(a).Get("/api/v1/auth/sessions")
	s.Require().NoError(err)
	var rows []map[string]any
	s.Require().NoError(resp.Bind(&rows))
	s.Require().Len(rows, 2)
	var otherID string
	for _, r := range rows {
		if cur, _ := r["current"].(bool); !cur {
			otherID, _ = r["id"].(string)
		}
	}
	s.Require().NotEmpty(otherID)

	// A terminates B.
	del, err := s.Http(t).WithCookie(a).Delete("/api/v1/auth/sessions/"+otherID, nil)
	s.Require().NoError(err)
	del.AssertStatus(http.StatusOK)

	// B's next request is rejected as terminated; A stays alive.
	bResp, err := s.Http(t).WithCookie(b).Get("/api/v1/auth/me")
	s.Require().NoError(err)
	bResp.AssertStatus(http.StatusUnauthorized)

	aResp, err := s.Http(t).WithCookie(a).Get("/api/v1/auth/me")
	s.Require().NoError(err)
	aResp.AssertStatus(http.StatusOK)
}

func (s *SessionsTestSuite) TestCannotTerminateCurrent() {
	t := s.T()
	a := s.login("Device-A/1.0")

	resp, err := s.Http(t).WithCookie(a).Get("/api/v1/auth/sessions")
	s.Require().NoError(err)
	var rows []map[string]any
	s.Require().NoError(resp.Bind(&rows))
	s.Require().Len(rows, 1)
	id, _ := rows[0]["id"].(string)

	del, err := s.Http(t).WithCookie(a).Delete("/api/v1/auth/sessions/"+id, nil)
	s.Require().NoError(err)
	del.AssertStatus(http.StatusBadRequest)
}

func (s *SessionsTestSuite) TestLoginHistory() {
	t := s.T()
	c := s.login("Device-A/1.0")

	resp, err := s.Http(t).WithCookie(c).Get("/api/v1/auth/logins")
	s.Require().NoError(err)
	resp.AssertStatus(http.StatusOK)
	var entries []map[string]any
	s.Require().NoError(resp.Bind(&entries))
	s.Require().NotEmpty(entries)
	s.Equal("auth.login", entries[0]["action"])
}
