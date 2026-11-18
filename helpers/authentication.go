package helpers

import (
	"encoding/json"
	"time"

	"github.com/freshost/goravel-authkit/models"
	contractshttp "github.com/goravel/framework/contracts/http"
)

// Authentication records a completed interactive authentication, not session
// creation or remember-cookie rotation. It is deliberately guard-scoped.
type Authentication struct {
	At             time.Time `json:"at"`
	Event          string    `json:"event"`
	Methods        []string  `json:"methods"`
	TwoFactorStamp string    `json:"twoFactorStamp"`
}

func AuthenticationKey(guard string) string { return "authkit_" + guard + "_authentication" }

func RecordAuthentication(ctx contractshttp.Context, guard string, methods []string, user *models.User) {
	if session := ctx.Request().Session(); session != nil {
		event := NewSessionToken()
		if event == "" {
			session.Forget(AuthenticationKey(guard))
			return
		}
		data, err := json.Marshal(Authentication{At: time.Now().UTC(), Event: event, Methods: methods, TwoFactorStamp: user.TwoFactorCredentialStamp()})
		if err == nil {
			session.Put(AuthenticationKey(guard), string(data))
		}
	}
}

func SessionAuthentication(ctx contractshttp.Context, guard string) Authentication {
	var result Authentication
	if session := ctx.Request().Session(); session != nil {
		raw, _ := session.Get(AuthenticationKey(guard)).(string)
		_ = json.Unmarshal([]byte(raw), &result)
	}
	return result
}

func ClearAuthentication(ctx contractshttp.Context, guard string) {
	if session := ctx.Request().Session(); session != nil {
		session.Forget(AuthenticationKey(guard))
	}
}

// PendingAuthentication contains only the proof verified at the password step.
type PendingAuthentication struct {
	PasswordStamp  time.Time `json:"passwordStamp"`
	TwoFactorStamp string    `json:"twoFactorStamp"`
	ExpiresAt      time.Time `json:"expiresAt"`
}

func PendingAuthenticationKey(guard string) string {
	return "authkit_" + guard + "_pending_authentication"
}
