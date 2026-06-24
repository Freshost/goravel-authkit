package feature

import (
	"bytes"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	testhttp "github.com/goravel/framework/contracts/testing/http"
	"github.com/goravel/framework/facades"
	"github.com/stretchr/testify/suite"

	authmodels "github.com/freshost/goravel-authkit/models"

	"goravel/tests"
)

// MultiInstanceTestSuite exercises two independent authkit instances mounted in
// one app: the admin portal (/api/v1, guard "admin", table "users") and the
// client portal (/api/client/v1, guard "client", table "client_users"). It
// asserts the domains are disjoint, that one shared session cookie carries both
// guards without collision, and that each instance issues its own remember cookie.
type MultiInstanceTestSuite struct {
	suite.Suite
	tests.TestCase
	adminEmail  string
	clientEmail string
	password    string
}

func TestMultiInstanceTestSuite(t *testing.T) {
	suite.Run(t, new(MultiInstanceTestSuite))
}

func (s *MultiInstanceTestSuite) SetupTest() {
	s.password = "password123"
	s.adminEmail = "mi-admin-" + uuid.NewString() + "@test.local"
	s.clientEmail = "mi-client-" + uuid.NewString() + "@test.local"

	hash, err := facades.Hash().Make(s.password)
	s.Require().NoError(err)

	// Admin lives in the default "users" table.
	s.Require().NoError(facades.Orm().Query().Create(&authmodels.User{
		ID:                uuid.New(),
		Email:             s.adminEmail,
		PasswordHash:      &hash,
		Role:              "admin",
		PasswordChangedAt: time.Now().UTC(),
	}))
	// Client lives in the separate "client_users" table.
	s.Require().NoError(facades.Orm().Query().Table("client_users").Create(&authmodels.User{
		ID:                uuid.New(),
		Email:             s.clientEmail,
		PasswordHash:      &hash,
		Role:              "user",
		PasswordChangedAt: time.Now().UTC(),
	}))
}

func (s *MultiInstanceTestSuite) TearDownTest() {
	_, _ = facades.Orm().Query().Where("email", s.adminEmail).Delete(&authmodels.User{})
	_, _ = facades.Orm().Query().Table("client_users").Where("email", s.clientEmail).Delete(&authmodels.User{})
}

// cookieNamed returns the LAST cookie with the given name. Login regenerates the
// session and re-emits the session cookie, so the response carries two Set-Cookie
// headers for it; the last one (the regenerated id) is the live session, matching
// browser semantics.
func cookieNamed(resp interface{ Cookies() []*http.Cookie }, name string) *http.Cookie {
	var found *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == name {
			found = c
		}
	}
	return found
}

func (s *MultiInstanceTestSuite) login(t *testing.T, prefix, email string) (testhttp.Response, *http.Cookie) {
	body := `{"email":"` + email + `","password":"` + s.password + `"}`
	resp, err := s.Http(t).WithHeader("Content-Type", "application/json").
		Post(prefix+"/auth/login", bytes.NewBufferString(body))
	s.Require().NoError(err)
	return resp, cookieNamed(resp, "authkit_demo_session")
}

// Each user authenticates only against its own instance's table: the admin user
// is unknown to the client portal and vice versa.
func (s *MultiInstanceTestSuite) TestDomainsAreDisjoint() {
	t := s.T()

	resp, cookie := s.login(t, "/api/v1", s.adminEmail)
	resp.AssertOk()
	s.Require().NotNil(cookie, "admin logs into the admin portal")

	resp, _ = s.login(t, "/api/client/v1", s.clientEmail)
	resp.AssertOk()

	resp, _ = s.login(t, "/api/client/v1", s.adminEmail)
	resp.AssertUnauthorized()

	resp, _ = s.login(t, "/api/v1", s.clientEmail)
	resp.AssertUnauthorized()
}

// The two guards are isolated within the one shared session cookie: an admin
// login authenticates the admin portal but NOT the client portal on the same
// cookie. Goravel keys each guard's user id separately (auth_admin_id vs
// auth_client_id), so authenticating one guard never leaks into the other.
//
// (Logging a single browser into BOTH portals at once is out of scope: each
// login rotates the shared session id for session-fixation protection, which
// orphans the other instance's active-session tracking row. The realistic
// deployment is two separate SPAs — one login at a time; a host that truly needs
// concurrent dual-login gives each instance a distinct session cookie name/path.)
func (s *MultiInstanceTestSuite) TestGuardsIsolatedInSharedCookie() {
	t := s.T()

	resp, adminCookie := s.login(t, "/api/v1", s.adminEmail)
	resp.AssertOk()
	s.Require().NotNil(adminCookie)

	// The admin session authenticates the admin portal.
	me, err := s.Http(t).WithCookie(adminCookie).Get("/api/v1/auth/me")
	s.Require().NoError(err)
	me.AssertOk()
	adminJSON, err := me.Json()
	s.Require().NoError(err)
	s.Equal(s.adminEmail, adminJSON["email"])

	// The SAME cookie does not authenticate the client portal — the client guard
	// has no id in this session.
	clientMe, err := s.Http(t).WithCookie(adminCookie).Get("/api/client/v1/auth/me")
	s.Require().NoError(err)
	clientMe.AssertUnauthorized()
}

// Each instance issues its own remember cookie name, so the two portals on one
// origin don't overwrite each other's persistent login.
func (s *MultiInstanceTestSuite) TestSeparateRememberCookies() {
	t := s.T()

	body := `{"email":"` + s.clientEmail + `","password":"` + s.password + `","remember":true}`
	resp, err := s.Http(t).WithHeader("Content-Type", "application/json").
		Post("/api/client/v1/auth/login", bytes.NewBufferString(body))
	s.Require().NoError(err)
	resp.AssertStatus(http.StatusOK)
	s.NotNil(cookieNamed(resp, "authkit_client_remember"), "client issues its own remember cookie")
	s.Nil(cookieNamed(resp, "authkit_remember"), "client must not use the default remember cookie name")

	body = `{"email":"` + s.adminEmail + `","password":"` + s.password + `","remember":true}`
	resp, err = s.Http(t).WithHeader("Content-Type", "application/json").
		Post("/api/v1/auth/login", bytes.NewBufferString(body))
	s.Require().NoError(err)
	resp.AssertStatus(http.StatusOK)
	s.NotNil(cookieNamed(resp, "authkit_remember"), "admin uses the default remember cookie")
	s.Nil(cookieNamed(resp, "authkit_client_remember"), "admin must not use the client remember cookie name")
}

// Logging into BOTH portals in one browser keeps both authenticated even with
// active-session tracking on. Previously this regressed: the second login rotated
// the shared session id and orphaned the first guard's tracking row, so the first
// portal's next request 401'd with session_terminated. Active-session tracking is
// now keyed by a stable per-guard token that survives the rotation.
func (s *MultiInstanceTestSuite) TestConcurrentDualLoginKeepsBothTracked() {
	t := s.T()

	admin, adminCookie := s.login(t, "/api/v1", s.adminEmail)
	admin.AssertOk()
	s.Require().NotNil(adminCookie)

	// Log into the client portal carrying the admin session cookie; this rotates
	// the shared session id.
	body := `{"email":"` + s.clientEmail + `","password":"` + s.password + `"}`
	resp, err := s.Http(t).WithHeader("Content-Type", "application/json").WithCookie(adminCookie).
		Post("/api/client/v1/auth/login", bytes.NewBufferString(body))
	s.Require().NoError(err)
	resp.AssertOk()
	bothCookie := cookieNamed(resp, "authkit_demo_session")
	s.Require().NotNil(bothCookie)

	// Admin portal still works (its tracking row survived the id rotation) — this
	// is the request that previously returned session_terminated.
	me, err := s.Http(t).WithCookie(bothCookie).Get("/api/v1/auth/me")
	s.Require().NoError(err)
	me.AssertOk()
	adminJSON, err := me.Json()
	s.Require().NoError(err)
	s.Equal(s.adminEmail, adminJSON["email"])

	// And the client portal works on the same cookie.
	clientMe, err := s.Http(t).WithCookie(bothCookie).Get("/api/client/v1/auth/me")
	s.Require().NoError(err)
	clientMe.AssertOk()
	clientJSON, err := clientMe.Json()
	s.Require().NoError(err)
	s.Equal(s.clientEmail, clientJSON["email"])
}
