package services

import "github.com/goravel/framework/facades"

// Hasher abstracts password hashing so services can be unit-tested without
// booting the framework. The default implementation delegates to the Goravel
// Hash facade (configure bcrypt cost 12 in config/hashing.go).
type Hasher interface {
	Make(value string) (string, error)
	Check(value, hashed string) bool
}

// FacadeHasher is the production Hasher, backed by facades.Hash().
type FacadeHasher struct{}

// NewFacadeHasher returns a Hasher backed by the Goravel Hash facade.
func NewFacadeHasher() FacadeHasher { return FacadeHasher{} }

var _ Hasher = FacadeHasher{}

func (FacadeHasher) Make(value string) (string, error) { return facades.Hash().Make(value) }

func (FacadeHasher) Check(value, hashed string) bool { return facades.Hash().Check(value, hashed) }
