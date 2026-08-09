package services

import (
	"context"
	"errors"
	"slices"

	"github.com/freshost/goravel-authkit/contracts"
)

// Impersonation is the per-actor-guard authorization gate for user impersonation.
// It enforces the declarative config rules and then, if registered, the host's
// fine-grained hook — both must allow (fail-closed).
type Impersonation struct {
	roles          []string // actor must hold one of these roles (empty = any authenticated user)
	targetGuards   []string // guards the actor may impersonate into ("*" = any; include the actor's own guard for same-guard)
	protectedRoles []string // target roles that may never be impersonated
}

// NewImpersonation builds the gate from a guard's impersonation config.
func NewImpersonation(roles, targetGuards, protectedRoles []string) *Impersonation {
	return &Impersonation{roles: roles, targetGuards: targetGuards, protectedRoles: protectedRoles}
}

// CanTargetGuard reports whether this actor guard is configured to impersonate
// into targetGuard at all (used to fail fast before loading the target).
func (s *Impersonation) CanTargetGuard(targetGuard string) bool {
	return slices.Contains(s.targetGuards, "*") || slices.Contains(s.targetGuards, targetGuard)
}

// Authorize runs the layered gate for a concrete (actor, target) pair: the config
// rules first (actor role, target guard, protected target role), then the optional
// host hook. Returns nil when allowed, ErrForbidden when denied, ErrInternal when
// the hook itself errors.
func (s *Impersonation) Authorize(ctx context.Context, actor contracts.Principal, targetGuard string, target contracts.Principal) error {
	if len(s.roles) > 0 && !slices.Contains(s.roles, actor.Role) {
		return ErrForbidden
	}
	if !s.CanTargetGuard(targetGuard) {
		return ErrForbidden
	}
	if slices.Contains(s.protectedRoles, target.Role) {
		return ErrForbidden
	}
	if policy := contracts.ImpersonationPolicy(); policy != nil {
		ok, err := policy.CanImpersonate(ctx, actor, targetGuard, target)
		if err != nil {
			return errors.Join(ErrInternal, err)
		}
		if !ok {
			return ErrForbidden
		}
	}
	return nil
}
