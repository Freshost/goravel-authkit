package tests

import (
	frameworkcontracts "github.com/goravel/framework/contracts/testing"
	contractshttp "github.com/goravel/framework/contracts/testing/http"
	"github.com/goravel/framework/testing"

	"goravel/bootstrap"
)

// NOTE: the feature suite performs many logins from one IP in a single process.
// Run it with all AUTHKIT_RATE_LIMIT_*_ATTEMPTS values set high (the `make test`
// target does this) so shared test identities and addresses do not throttle.
func init() {
	bootstrap.Boot()
}

type TestCase struct {
	testing.TestCase
}

// Http identifies feature requests as same-origin browser traffic. Authkit's
// CSRF middleware deliberately rejects unsafe requests with no trusted browser
// origin signal.
func (testCase *TestCase) Http(t frameworkcontracts.TestingT) contractshttp.Request {
	return testCase.TestCase.Http(t).WithHeader("Sec-Fetch-Site", "same-origin")
}
