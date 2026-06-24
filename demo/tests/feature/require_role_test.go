package feature

import (
	"bytes"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	contractstesting "github.com/goravel/framework/contracts/testing/http"
	"github.com/goravel/framework/facades"
	"github.com/stretchr/testify/suite"

	authmodels "github.com/freshost/goravel-authkit/models"

	"goravel/tests"
)

// RequireRoleTestSuite verifies the RequireRole gate on the /users admin block
// for EVERY verb: a non-admin (role "user") is forbidden (403) on each of the
// six endpoints, while an admin reaches them (2xx). This complements
// user_management_test.go, which only covers GET-list and POST.
type RequireRoleTestSuite struct {
	suite.Suite
	tests.TestCase
	adminEmail  string
	memberEmail string
	targetID    string // an existing user the verbs address
	password    string
}

func TestRequireRoleTestSuite(t *testing.T) {
	suite.Run(t, new(RequireRoleTestSuite))
}

func (s *RequireRoleTestSuite) SetupTest() {
	s.password = "password123"
	suffix := uuid.NewString()
	s.adminEmail = "rr-admin-" + suffix + "@test.local"
	s.memberEmail = "rr-member-" + suffix + "@test.local"
	s.seedUser(s.adminEmail, "admin")
	s.seedUser(s.memberEmail, "user")

	// A throwaway target user the show/update/delete/set-password verbs address.
	target := &authmodels.User{
		ID:                uuid.New(),
		Email:             "rr-target-" + suffix + "@test.local",
		Role:              "user",
		PasswordChangedAt: time.Now().UTC(),
	}
	hash, err := facades.Hash().Make(s.password)
	s.Require().NoError(err)
	target.PasswordHash = &hash
	s.Require().NoError(facades.Orm().Query().Create(target))
	s.targetID = target.ID.String()
}

func (s *RequireRoleTestSuite) TearDownTest() {
	for _, e := range []string{s.adminEmail, s.memberEmail} {
		_, _ = facades.Orm().Query().Where("email", e).Delete(&authmodels.User{})
	}
	if s.targetID != "" {
		_, _ = facades.Orm().Query().Where("id", s.targetID).Delete(&authmodels.User{})
	}
}

func (s *RequireRoleTestSuite) seedUser(email, role string) {
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

func (s *RequireRoleTestSuite) login(email string) *http.Cookie {
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

// A non-admin is forbidden (403) from every /users verb.
func (s *RequireRoleTestSuite) TestNonAdminForbiddenOnEveryVerb() {
	t := s.T()
	c := s.login(s.memberEmail)
	json := func() string { return `{"email":"x@test.local","name":"X","role":"user"}` }

	cases := []struct {
		name string
		do   func() (contractstesting.Response, error)
	}{
		{"GET list", func() (contractstesting.Response, error) {
			return s.Http(t).WithCookie(c).Get("/api/v1/auth/users")
		}},
		{"GET show", func() (contractstesting.Response, error) {
			return s.Http(t).WithCookie(c).Get("/api/v1/auth/users/" + s.targetID)
		}},
		{"POST create", func() (contractstesting.Response, error) {
			return s.Http(t).WithCookie(c).WithHeader("Content-Type", "application/json").
				Post("/api/v1/auth/users", bytes.NewBufferString(`{"email":"nope-`+uuid.NewString()+`@test.local","password":"password123","role":"user"}`))
		}},
		{"PUT update", func() (contractstesting.Response, error) {
			return s.Http(t).WithCookie(c).WithHeader("Content-Type", "application/json").
				Put("/api/v1/auth/users/"+s.targetID, bytes.NewBufferString(json()))
		}},
		{"DELETE", func() (contractstesting.Response, error) {
			return s.Http(t).WithCookie(c).Delete("/api/v1/auth/users/"+s.targetID, nil)
		}},
		{"POST set-password", func() (contractstesting.Response, error) {
			return s.Http(t).WithCookie(c).WithHeader("Content-Type", "application/json").
				Post("/api/v1/auth/users/"+s.targetID+"/password", bytes.NewBufferString(`{"password":"password123"}`))
		}},
	}
	for _, tc := range cases {
		resp, err := tc.do()
		s.Require().NoError(err, tc.name)
		resp.AssertStatus(http.StatusForbidden)
	}
}

// An admin reaches every /users verb (2xx). Mutating verbs target a throwaway
// user so the shared admin is never touched destructively.
func (s *RequireRoleTestSuite) TestAdminAllowedOnEveryVerb() {
	t := s.T()
	c := s.login(s.adminEmail)

	list, err := s.Http(t).WithCookie(c).Get("/api/v1/auth/users")
	s.Require().NoError(err)
	list.AssertStatus(http.StatusOK)

	show, err := s.Http(t).WithCookie(c).Get("/api/v1/auth/users/" + s.targetID)
	s.Require().NoError(err)
	show.AssertStatus(http.StatusOK)

	updateBody := `{"email":"rr-target-updated-` + uuid.NewString() + `@test.local","name":"Renamed","role":"user"}`
	update, err := s.Http(t).WithCookie(c).WithHeader("Content-Type", "application/json").
		Put("/api/v1/auth/users/"+s.targetID, bytes.NewBufferString(updateBody))
	s.Require().NoError(err)
	update.AssertStatus(http.StatusOK)

	setPw, err := s.Http(t).WithCookie(c).WithHeader("Content-Type", "application/json").
		Post("/api/v1/auth/users/"+s.targetID+"/password", bytes.NewBufferString(`{"password":"newpassword123"}`))
	s.Require().NoError(err)
	setPw.AssertStatus(http.StatusOK)

	createEmail := "rr-created-" + uuid.NewString() + "@test.local"
	defer func() { _, _ = facades.Orm().Query().Where("email", createEmail).Delete(&authmodels.User{}) }()
	create, err := s.Http(t).WithCookie(c).WithHeader("Content-Type", "application/json").
		Post("/api/v1/auth/users", bytes.NewBufferString(`{"email":"`+createEmail+`","password":"password123","role":"user"}`))
	s.Require().NoError(err)
	create.AssertStatus(http.StatusCreated)

	del, err := s.Http(t).WithCookie(c).Delete("/api/v1/auth/users/"+s.targetID, nil)
	s.Require().NoError(err)
	del.AssertStatus(http.StatusOK)
}
