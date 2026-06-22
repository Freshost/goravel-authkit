package tests

import (
	"github.com/goravel/framework/testing"

	"goravel/bootstrap"
)

// NOTE: the feature suite performs many logins from one IP in a single process.
// Run it with AUTHKIT_RATE_LIMIT_ATTEMPTS set high (the `make test` target does
// this) so the per-IP login rate limiter doesn't trip the tests.
func init() {
	bootstrap.Boot()
}

type TestCase struct {
	testing.TestCase
}
