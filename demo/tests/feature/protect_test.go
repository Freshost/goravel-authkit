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

// ProtectTestSuite verifies that authkitroutes.Protect guards a HOST-owned route
// behind a specific guard: the demo mounts /api/client/v1/portal/whoami behind the
// "client" guard. Only a logged-in client reaches it; an anonymous request and an
// admin session are both rejected.
type ProtectTestSuite struct {
	suite.Suite
	tests.TestCase
	clientID    uuid.UUID
	clientEmail string
	adminEmail  string
	password    string
}

func TestProtectTestSuite(t *testing.T) {
	suite.Run(t, new(ProtectTestSuite))
}

func (s *ProtectTestSuite) SetupTest() {
	s.password = "password123"
	s.clientID = uuid.New()
	s.clientEmail = "protect-client-" + uuid.NewString() + "@test.local"
	s.adminEmail = "protect-admin-" + uuid.NewString() + "@test.local"
	hash, err := facades.Hash().Make(s.password)
	s.Require().NoError(err)

	s.Require().NoError(facades.Orm().Query().Table("client_users").Create(&authmodels.User{
		ID: s.clientID, Email: s.clientEmail, PasswordHash: &hash, Role: "user",
		PasswordChangedAt: time.Now().UTC(),
	}))
	s.Require().NoError(facades.Orm().Query().Create(&authmodels.User{
		ID: uuid.New(), Email: s.adminEmail, PasswordHash: &hash, Role: "admin",
		PasswordChangedAt: time.Now().UTC(),
	}))
}

func (s *ProtectTestSuite) TearDownTest() {
	_, _ = facades.Orm().Query().Table("client_users").Where("email", s.clientEmail).Delete(&authmodels.User{})
	_, _ = facades.Orm().Query().Where("email", s.adminEmail).Delete(&authmodels.User{})
}

func (s *ProtectTestSuite) loginCookie(t *testing.T, prefix, email string) *http.Cookie {
	body := `{"email":"` + email + `","password":"` + s.password + `"}`
	resp, err := s.Http(t).WithHeader("Content-Type", "application/json").
		Post(prefix+"/auth/login", bytes.NewBufferString(body))
	s.Require().NoError(err)
	resp.AssertOk()
	return cookieNamed(resp, "authkit_demo_session")
}

func (s *ProtectTestSuite) TestAnonymousRejected() {
	resp, err := s.Http(s.T()).Get("/api/client/v1/portal/whoami")
	s.Require().NoError(err)
	resp.AssertUnauthorized()
}

func (s *ProtectTestSuite) TestClientReachesAndSeesOwnID() {
	t := s.T()
	cookie := s.loginCookie(t, "/api/client/v1", s.clientEmail)
	s.Require().NotNil(cookie)

	resp, err := s.Http(t).WithCookie(cookie).Get("/api/client/v1/portal/whoami")
	s.Require().NoError(err)
	resp.AssertOk()
	json, err := resp.Json()
	s.Require().NoError(err)
	s.Equal(s.clientID.String(), json["userId"], "handler sees the authenticated client id")
}

func (s *ProtectTestSuite) TestAdminSessionRejectedByClientGuard() {
	t := s.T()
	cookie := s.loginCookie(t, "/api/v1", s.adminEmail)
	s.Require().NotNil(cookie)

	resp, err := s.Http(t).WithCookie(cookie).Get("/api/client/v1/portal/whoami")
	s.Require().NoError(err)
	resp.AssertUnauthorized()
}
