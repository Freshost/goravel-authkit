package authkit

import "github.com/freshost/goravel-authkit/contracts"

// Principal identifies a party (actor or target) in an impersonation decision.
type Principal = contracts.Principal

// Impersonator is the host-implemented, fine-grained impersonation authorization
// hook. See contracts.Impersonator.
type Impersonator = contracts.Impersonator

// RegisterImpersonationPolicy registers the host's fine-grained impersonation
// authorization hook (optional — authkit's config gate decides when none is set).
// Call it once at boot. The hook runs only after the config gate has passed, so it
// can only tighten the decision.
func RegisterImpersonationPolicy(p Impersonator) { contracts.SetImpersonationPolicy(p) }
