package contracts

import (
	"context"

	"github.com/google/uuid"
)

// Principal identifies one party in an impersonation decision — the actor (the
// signed-in user requesting the switch) or the target (the user to be impersonated).
type Principal struct {
	Guard  string
	UserID uuid.UUID
	Email  string
	Role   string
}

// Impersonator is the optional, host-implemented authorization hook for the fine
// rules a declarative config gate cannot express (tenant scoping, relationship
// checks, "never impersonate someone above your level"). It runs AFTER authkit's
// config gate (required roles / allowed target guards / protected roles) has
// already passed, so it only ever tightens the decision. Return false to deny.
//
// Register it once at boot with authkit.RegisterImpersonationPolicy. When no hook
// is registered, the config gate alone decides.
type Impersonator interface {
	CanImpersonate(ctx context.Context, actor Principal, targetGuard string, target Principal) (bool, error)
}

// impersonationPolicy holds the process-global host hook (set once at boot,
// read-only afterwards).
var impersonationPolicy Impersonator

// SetImpersonationPolicy registers the host's fine-grained authorization hook.
func SetImpersonationPolicy(p Impersonator) { impersonationPolicy = p }

// ImpersonationPolicy returns the registered hook, or nil when none is set.
func ImpersonationPolicy() Impersonator { return impersonationPolicy }
