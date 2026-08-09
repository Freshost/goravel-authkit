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

// ImpersonationTestSuite exercises admin impersonation — same-guard and cross-guard
// — plus the layered authorization (role gate, protected roles, host hook), the
// reject-while-impersonating guards, and the ephemeral (no remember cookie) switch.
//
// Demo config: impersonation enabled globally; the "admin" guard may impersonate
// into "client" and "admin" with roles=["admin"] and protected_roles=["admin"]; the
// host hook refuses any target whose email carries "+nohook".
type ImpersonationTestSuite struct {
	suite.Suite
	tests.TestCase
	password string

	adminID, admin2ID, userID uuid.UUID
	clientID, hookID          uuid.UUID

	adminEmail, admin2Email, userEmail string
	clientEmail, hookEmail             string
}

func TestImpersonationTestSuite(t *testing.T) {
	suite.Run(t, new(ImpersonationTestSuite))
}

func (s *ImpersonationTestSuite) mkUser(table, email, role string) uuid.UUID {
	hash, err := facades.Hash().Make(s.password)
	s.Require().NoError(err)
	id := uuid.New()
	u := &authmodels.User{ID: id, Email: email, PasswordHash: &hash, Role: role, PasswordChangedAt: time.Now().UTC()}
	if table == "" {
		s.Require().NoError(facades.Orm().Query().Create(u))
	} else {
		s.Require().NoError(facades.Orm().Query().Table(table).Create(u))
	}
	return id
}

func (s *ImpersonationTestSuite) SetupTest() {
	s.password = "password123"
	tag := uuid.NewString()
	s.adminEmail = "imp-admin-" + tag + "@test.local"
	s.admin2Email = "imp-admin2-" + tag + "@test.local"
	s.userEmail = "imp-user-" + tag + "@test.local"
	s.clientEmail = "imp-client-" + tag + "@test.local"
	s.hookEmail = "imp-hook-" + tag + "+nohook@test.local"

	s.adminID = s.mkUser("", s.adminEmail, "admin")
	s.admin2ID = s.mkUser("", s.admin2Email, "admin")
	s.userID = s.mkUser("", s.userEmail, "user")
	s.clientID = s.mkUser("client_users", s.clientEmail, "user")
	s.hookID = s.mkUser("client_users", s.hookEmail, "user")
}

func (s *ImpersonationTestSuite) TearDownTest() {
	for _, e := range []string{s.adminEmail, s.admin2Email, s.userEmail} {
		_, _ = facades.Orm().Query().Where("email", e).Delete(&authmodels.User{})
	}
	for _, e := range []string{s.clientEmail, s.hookEmail} {
		_, _ = facades.Orm().Query().Table("client_users").Where("email", e).Delete(&authmodels.User{})
	}
}

func (s *ImpersonationTestSuite) login(t *testing.T, prefix, email string) *http.Cookie {
	body := `{"email":"` + email + `","password":"` + s.password + `"}`
	resp, err := s.Http(t).WithHeader("Content-Type", "application/json").
		Post(prefix+"/auth/login", bytes.NewBufferString(body))
	s.Require().NoError(err)
	resp.AssertOk()
	return cookieNamed(resp, "authkit_demo_session") // before any Json()
}

func (s *ImpersonationTestSuite) impersonate(t *testing.T, prefix string, cookie *http.Cookie, guard, userID string) testhttp.Response {
	body := `{"guard":"` + guard + `","userId":"` + userID + `"}`
	resp, err := s.Http(t).WithHeader("Content-Type", "application/json").WithCookie(cookie).
		Post(prefix+"/auth/impersonate", bytes.NewBufferString(body))
	s.Require().NoError(err)
	return resp
}

// meEmail GETs /me and returns (status-ok, email, impersonatedBy-map). The order is
// important: read the status, then the body — never the cookie after Json.
func (s *ImpersonationTestSuite) me(t *testing.T, prefix string, cookie *http.Cookie) (testhttp.Response, map[string]any) {
	resp, err := s.Http(t).WithCookie(cookie).Get(prefix + "/auth/me")
	s.Require().NoError(err)
	return resp, nil
}

// Same-guard: an admin impersonates a regular user in the same table; /me reflects
// the target with an impersonatedBy marker; stop restores the admin.
func (s *ImpersonationTestSuite) TestSameGuard() {
	t := s.T()
	cookie := s.login(t, "/api/v1", s.adminEmail)
	s.Require().NotNil(cookie)

	resp := s.impersonate(t, "/api/v1", cookie, "admin", s.userID.String())
	resp.AssertOk()
	c2 := cookieNamed(resp, "authkit_demo_session")
	s.Require().NotNil(c2)
	body, _ := resp.Json()
	s.Equal(s.userEmail, body["email"], "impersonate returns the target user")

	me, _ := s.me(t, "/api/v1", c2)
	me.AssertOk()
	mj, _ := me.Json()
	s.Equal(s.userEmail, mj["email"])
	imp, _ := mj["impersonatedBy"].(map[string]any)
	s.Require().NotNil(imp, "/me exposes impersonatedBy while impersonating")
	s.Equal(s.adminID.String(), imp["id"])

	stop, err := s.Http(t).WithCookie(c2).Post("/api/v1/auth/impersonate/stop", bytes.NewReader(nil))
	s.Require().NoError(err)
	stop.AssertOk()
	c3 := cookieNamed(stop, "authkit_demo_session")
	s.Require().NotNil(c3)

	me2, _ := s.me(t, "/api/v1", c3)
	me2.AssertOk()
	mj2, _ := me2.Json()
	s.Equal(s.adminEmail, mj2["email"], "stop restores the original admin")
	s.Nil(mj2["impersonatedBy"])
}

// Cross-guard: an admin impersonates a client; the admin's own session stays live
// alongside the impersonated client session, and stop drops only the client one.
func (s *ImpersonationTestSuite) TestCrossGuard() {
	t := s.T()
	cookie := s.login(t, "/api/v1", s.adminEmail)

	resp := s.impersonate(t, "/api/v1", cookie, "client", s.clientID.String())
	resp.AssertOk()
	both := cookieNamed(resp, "authkit_demo_session")
	s.Require().NotNil(both)

	// Client portal resolves the impersonated client...
	cm, _ := s.me(t, "/api/client/v1", both)
	cm.AssertOk()
	cmj, _ := cm.Json()
	s.Equal(s.clientEmail, cmj["email"])
	imp, _ := cmj["impersonatedBy"].(map[string]any)
	s.Require().NotNil(imp)
	s.Equal(s.adminID.String(), imp["id"])

	// ...while the admin portal still resolves the admin (session intact).
	am, _ := s.me(t, "/api/v1", both)
	am.AssertOk()
	amj, _ := am.Json()
	s.Equal(s.adminEmail, amj["email"])
	s.Nil(amj["impersonatedBy"])

	// Stop on the client guard ends only the client session.
	stop, err := s.Http(t).WithCookie(both).Post("/api/client/v1/auth/impersonate/stop", bytes.NewReader(nil))
	s.Require().NoError(err)
	stop.AssertOk()
	c3 := cookieNamed(stop, "authkit_demo_session")
	s.Require().NotNil(c3)

	cmAfter, _ := s.me(t, "/api/client/v1", c3)
	cmAfter.AssertUnauthorized()
	amAfter, _ := s.me(t, "/api/v1", c3)
	amAfter.AssertOk()
	amj2, _ := amAfter.Json()
	s.Equal(s.adminEmail, amj2["email"], "admin session survives ending the impersonation")
}

// A non-admin actor is denied by the role gate.
func (s *ImpersonationTestSuite) TestRoleGateDenies() {
	t := s.T()
	cookie := s.login(t, "/api/v1", s.userEmail) // role "user"
	resp := s.impersonate(t, "/api/v1", cookie, "admin", s.adminID.String())
	resp.AssertForbidden()
}

// A protected-role target (another admin) cannot be impersonated.
func (s *ImpersonationTestSuite) TestProtectedRoleDenies() {
	t := s.T()
	cookie := s.login(t, "/api/v1", s.adminEmail)
	resp := s.impersonate(t, "/api/v1", cookie, "admin", s.admin2ID.String())
	resp.AssertForbidden()
}

// The host hook denies a target the config gate would otherwise allow.
func (s *ImpersonationTestSuite) TestHookDenies() {
	t := s.T()
	cookie := s.login(t, "/api/v1", s.adminEmail)
	resp := s.impersonate(t, "/api/v1", cookie, "client", s.hookID.String())
	resp.AssertForbidden()
}

// While impersonating, credential/privilege actions and nested impersonation are
// rejected.
func (s *ImpersonationTestSuite) TestRejectsSensitiveActionsWhileImpersonating() {
	t := s.T()
	cookie := s.login(t, "/api/v1", s.adminEmail)
	resp := s.impersonate(t, "/api/v1", cookie, "client", s.clientID.String())
	resp.AssertOk()
	both := cookieNamed(resp, "authkit_demo_session")
	s.Require().NotNil(both)

	pw, err := s.Http(t).WithHeader("Content-Type", "application/json").WithCookie(both).
		Put("/api/client/v1/auth/password", bytes.NewBufferString(`{}`))
	s.Require().NoError(err)
	pw.AssertForbidden()

	nested, err := s.Http(t).WithHeader("Content-Type", "application/json").WithCookie(both).
		Post("/api/client/v1/auth/impersonate", bytes.NewBufferString(`{"userId":"`+s.clientID.String()+`"}`))
	s.Require().NoError(err)
	nested.AssertForbidden()
}

// Impersonation must not issue a persistent remember cookie.
func (s *ImpersonationTestSuite) TestNoRememberCookie() {
	t := s.T()
	cookie := s.login(t, "/api/v1", s.adminEmail)
	resp := s.impersonate(t, "/api/v1", cookie, "client", s.clientID.String())
	resp.AssertOk()
	s.Nil(cookieNamed(resp, "authkit_remember"), "no admin remember cookie")
	s.Nil(cookieNamed(resp, "authkit_client_remember"), "no client remember cookie")
}
