package feature

import (
	"testing"

	"github.com/stretchr/testify/suite"

	"goravel/tests"
)

// PerGuardConfigTestSuite verifies that settings declared at the authkit root
// apply to every guard, while a guard can override them — proven through each
// guard's public /auth/meta payload. The demo sets a global min_password_length
// of 8 with 2FA on; the client guard overrides to 12 with 2FA off.
type PerGuardConfigTestSuite struct {
	suite.Suite
	tests.TestCase
}

func TestPerGuardConfigTestSuite(t *testing.T) {
	suite.Run(t, new(PerGuardConfigTestSuite))
}

func (s *PerGuardConfigTestSuite) meta(prefix string) map[string]any {
	resp, err := s.Http(s.T()).Get(prefix + "/auth/meta")
	s.Require().NoError(err)
	resp.AssertOk()
	json, err := resp.Json()
	s.Require().NoError(err)
	return json
}

// The admin guard inherits the global defaults; the client guard applies its
// per-guard overrides.
func (s *PerGuardConfigTestSuite) TestMetaReflectsPerGuardOverrides() {
	admin := s.meta("/api/v1")
	client := s.meta("/api/client/v1")

	// min_password_length: global 8 (admin) vs per-guard 12 (client).
	s.EqualValues(8, admin["minPasswordLength"], "admin inherits the global password policy")
	s.EqualValues(12, client["minPasswordLength"], "client overrides the password policy")

	// features.two_factor: global true (admin) vs per-guard false (client).
	adminFeatures, _ := admin["features"].(map[string]any)
	clientFeatures, _ := client["features"].(map[string]any)
	s.Require().NotNil(adminFeatures)
	s.Require().NotNil(clientFeatures)
	s.Equal(true, adminFeatures["twoFactor"], "admin inherits the global 2FA feature")
	s.Equal(false, clientFeatures["twoFactor"], "client disables 2FA per guard")
}
