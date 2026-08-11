package feature

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/stretchr/testify/suite"

	"goravel/tests"
)

type SecurityHardeningTestSuite struct {
	suite.Suite
	tests.TestCase
}

func TestSecurityHardeningTestSuite(t *testing.T) {
	suite.Run(t, new(SecurityHardeningTestSuite))
}

func (suite *SecurityHardeningTestSuite) TestCSRFRejectsMissingSignalsAndUntrustedOrigins() {
	body := []byte(`{"email":"nobody@example.com","password":"password123"}`)

	missing, err := suite.TestCase.TestCase.Http(suite.T()).
		WithHeader("Content-Type", "application/json").
		Post("/api/v1/auth/login", bytes.NewReader(body))
	suite.Require().NoError(err)
	missing.AssertStatus(http.StatusForbidden)
	missingJSON, err := missing.Json()
	suite.Require().NoError(err)
	suite.Equal("csrf_failed", missingJSON["error"])

	untrusted, err := suite.TestCase.TestCase.Http(suite.T()).
		WithHeader("Content-Type", "application/json").
		WithHeader("Origin", "https://attacker.example").
		Post("/api/v1/auth/login", bytes.NewReader(body))
	suite.Require().NoError(err)
	untrusted.AssertStatus(http.StatusForbidden)
}
