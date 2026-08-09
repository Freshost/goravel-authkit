package helpers

import (
	"encoding/json"

	"github.com/google/uuid"
	contractshttp "github.com/goravel/framework/contracts/http"
)

// ImpersonatorMarker records who is impersonating the session's user under a given
// guard, so the switch can be reversed and surfaced to the UI. It is stored as a
// JSON string in the session (server-side) under ImpersonatorKey(guard).
type ImpersonatorMarker struct {
	Guard     string    `json:"guard"`     // the impersonator's (actor's) guard
	UserID    uuid.UUID `json:"userId"`    // the impersonator's user id
	Email     string    `json:"email"`     // the impersonator's email (for the UI banner)
	SameGuard bool      `json:"sameGuard"` // true when actor and target share a guard
}

// ImpersonatorKey is the session key holding the impersonation marker for a guard.
func ImpersonatorKey(guard string) string {
	return "authkit_" + guard + "_impersonator"
}

// SetImpersonator records that the session's user under targetGuard is being
// impersonated by m.
func SetImpersonator(ctx contractshttp.Context, targetGuard string, m ImpersonatorMarker) {
	sess := ctx.Request().Session()
	if sess == nil {
		return
	}
	if b, err := json.Marshal(m); err == nil {
		sess.Put(ImpersonatorKey(targetGuard), string(b))
	}
}

// Impersonator returns the impersonation marker for targetGuard, or ok=false when
// the session is not an impersonated one.
func Impersonator(ctx contractshttp.Context, targetGuard string) (ImpersonatorMarker, bool) {
	sess := ctx.Request().Session()
	if sess == nil {
		return ImpersonatorMarker{}, false
	}
	raw, ok := sess.Get(ImpersonatorKey(targetGuard)).(string)
	if !ok || raw == "" {
		return ImpersonatorMarker{}, false
	}
	var m ImpersonatorMarker
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return ImpersonatorMarker{}, false
	}
	return m, true
}

// ClearImpersonator removes the impersonation marker for targetGuard.
func ClearImpersonator(ctx contractshttp.Context, targetGuard string) {
	sess := ctx.Request().Session()
	if sess == nil {
		return
	}
	sess.Forget(ImpersonatorKey(targetGuard))
}

// IsImpersonating reports whether the request's session under guard is impersonated.
func IsImpersonating(ctx contractshttp.Context, guard string) bool {
	_, ok := Impersonator(ctx, guard)
	return ok
}
