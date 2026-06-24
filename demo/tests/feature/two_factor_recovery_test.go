package feature

import (
	"bytes"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/goravel/framework/facades"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/suite"

	authmodels "github.com/freshost/goravel-authkit/models"

	"goravel/tests"
)

// TwoFactorRecoveryTestSuite drives the recovery-code security fix (M2) entirely
// over HTTP against a throwaway user. TOTP codes are computed locally from the
// plaintext secret the enrollment endpoint returns (github.com/pquerna/otp is a
// package dependency). It asserts:
//   - confirm returns plaintext recovery codes,
//   - GET /recovery-codes returns only {"remaining": N}, never plaintext,
//   - consuming a recovery code at the login challenge works and decrements the
//     remaining count,
//   - regenerate returns a brand-new plaintext set and invalidates the old codes.
type TwoFactorRecoveryTestSuite struct {
	suite.Suite
	tests.TestCase
	email    string
	password string
}

func TestTwoFactorRecoveryTestSuite(t *testing.T) {
	suite.Run(t, new(TwoFactorRecoveryTestSuite))
}

func (s *TwoFactorRecoveryTestSuite) SetupTest() {
	s.email = "tfa-" + uuid.NewString() + "@test.local"
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

func (s *TwoFactorRecoveryTestSuite) TearDownTest() {
	_, _ = facades.Orm().Query().Where("email", s.email).Delete(&authmodels.User{})
}

// login performs a password-only login and returns the session cookie.
func (s *TwoFactorRecoveryTestSuite) login() *http.Cookie {
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

// enroll runs Enable + Confirm over HTTP and returns the session cookie and the
// plaintext recovery codes shown once at confirmation.
func (s *TwoFactorRecoveryTestSuite) enroll() (*http.Cookie, []string) {
	t := s.T()
	cookie := s.login()

	enableResp, err := s.Http(t).WithCookie(cookie).Post("/api/v1/auth/two-factor", nil)
	s.Require().NoError(err)
	enableResp.AssertStatus(http.StatusOK)
	enrollment, err := enableResp.Json()
	s.Require().NoError(err)
	secret, _ := enrollment["secret"].(string)
	s.Require().NotEmpty(secret, "enrollment must return the TOTP secret")

	code, err := totp.GenerateCode(secret, time.Now().UTC())
	s.Require().NoError(err)

	confirmResp, err := s.Http(t).WithCookie(cookie).WithHeader("Content-Type", "application/json").
		Post("/api/v1/auth/two-factor/confirm", bytes.NewBufferString(`{"code":"`+code+`"}`))
	s.Require().NoError(err)
	confirmResp.AssertStatus(http.StatusOK)

	var confirmed struct {
		RecoveryCodes []string `json:"recoveryCodes"`
	}
	s.Require().NoError(confirmResp.Bind(&confirmed))
	s.Require().Len(confirmed.RecoveryCodes, 8, "confirm must return the full recovery-code set in plaintext")
	for _, rc := range confirmed.RecoveryCodes {
		s.NotEmpty(rc)
	}
	return cookie, confirmed.RecoveryCodes
}

// remainingCount fetches GET /recovery-codes and asserts plaintext codes are
// never exposed there, returning the reported remaining count.
func (s *TwoFactorRecoveryTestSuite) remainingCount(cookie *http.Cookie) int {
	t := s.T()
	resp, err := s.Http(t).WithCookie(cookie).Get("/api/v1/auth/two-factor/recovery-codes")
	s.Require().NoError(err)
	resp.AssertStatus(http.StatusOK)

	content, err := resp.Content()
	s.Require().NoError(err)
	s.NotContains(content, "recoveryCodes", "the status endpoint must never return plaintext codes")

	json, err := resp.Json()
	s.Require().NoError(err)
	remaining, ok := json["remaining"].(float64)
	s.Require().True(ok, "remaining must be present")
	return int(remaining)
}

func (s *TwoFactorRecoveryTestSuite) TestConfirmReturnsCodesAndStatusHidesThem() {
	cookie, codes := s.enroll()
	s.Equal(8, s.remainingCount(cookie), "all codes remain right after confirmation")
	s.Len(codes, 8)
}

// Consuming a recovery code via the login challenge works and decrements the
// remaining count.
func (s *TwoFactorRecoveryTestSuite) TestConsumeRecoveryCodeDecrements() {
	t := s.T()
	cookie, codes := s.enroll()
	s.Require().Equal(8, s.remainingCount(cookie))

	// A fresh password login now returns {two_factor:true} (session unauthenticated).
	loginBody := `{"email":"` + s.email + `","password":"` + s.password + `"}`
	loginResp, err := s.Http(t).WithHeader("Content-Type", "application/json").
		Post("/api/v1/auth/login", bytes.NewBufferString(loginBody))
	s.Require().NoError(err)
	loginResp.AssertStatus(http.StatusOK)
	loginJSON, err := loginResp.Json()
	s.Require().NoError(err)
	s.Require().Equal(true, loginJSON["two_factor"], "2FA-enabled login must require a challenge")

	// Carry the pending-challenge session cookie into the challenge.
	var pending *http.Cookie
	for _, c := range loginResp.Cookies() {
		if c.Name == "authkit_demo_session" {
			pending = c
		}
	}
	s.Require().NotNil(pending)

	// Complete the challenge with a single recovery code.
	chBody := `{"recoveryCode":"` + codes[0] + `"}`
	chResp, err := s.Http(t).WithCookie(pending).WithHeader("Content-Type", "application/json").
		Post("/api/v1/auth/two-factor-challenge", bytes.NewBufferString(chBody))
	s.Require().NoError(err)
	chResp.AssertStatus(http.StatusOK)

	// The remaining count dropped by exactly one.
	s.Equal(7, s.remainingCount(cookie), "consuming one recovery code decrements remaining")
}

// Regenerate returns a brand-new plaintext set and invalidates the old codes
// (an old code no longer completes a challenge).
func (s *TwoFactorRecoveryTestSuite) TestRegenerateInvalidatesOld() {
	t := s.T()
	cookie, oldCodes := s.enroll()

	regenResp, err := s.Http(t).WithCookie(cookie).Post("/api/v1/auth/two-factor/recovery-codes", nil)
	s.Require().NoError(err)
	regenResp.AssertStatus(http.StatusOK)
	var regen struct {
		RecoveryCodes []string `json:"recoveryCodes"`
	}
	s.Require().NoError(regenResp.Bind(&regen))
	s.Require().Len(regen.RecoveryCodes, 8)

	// The new set must differ from the old set.
	oldSet := map[string]bool{}
	for _, c := range oldCodes {
		oldSet[c] = true
	}
	for _, c := range regen.RecoveryCodes {
		s.False(oldSet[c], "regenerated codes must be new")
	}
	s.Equal(8, s.remainingCount(cookie), "regenerate resets remaining to the full set")

	// An OLD code must now fail the login challenge.
	loginBody := `{"email":"` + s.email + `","password":"` + s.password + `"}`
	loginResp, err := s.Http(t).WithHeader("Content-Type", "application/json").
		Post("/api/v1/auth/login", bytes.NewBufferString(loginBody))
	s.Require().NoError(err)
	var pending *http.Cookie
	for _, c := range loginResp.Cookies() {
		if c.Name == "authkit_demo_session" {
			pending = c
		}
	}
	s.Require().NotNil(pending)

	chBody := `{"recoveryCode":"` + oldCodes[0] + `"}`
	chResp, err := s.Http(t).WithCookie(pending).WithHeader("Content-Type", "application/json").
		Post("/api/v1/auth/two-factor-challenge", bytes.NewBufferString(chBody))
	s.Require().NoError(err)
	chResp.AssertStatus(http.StatusUnauthorized)
}
