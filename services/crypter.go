package services

import "github.com/goravel/framework/facades"

// Crypter abstracts symmetric encryption so the two-factor service can be
// unit-tested without booting the framework. The default implementation
// delegates to the Goravel Crypt facade (which uses the app key).
type Crypter interface {
	Encrypt(value string) (string, error)
	Decrypt(payload string) (string, error)
}

// FacadeCrypter is the production Crypter, backed by facades.Crypt().
type FacadeCrypter struct{}

// NewFacadeCrypter returns a Crypter backed by the Goravel Crypt facade.
func NewFacadeCrypter() FacadeCrypter { return FacadeCrypter{} }

var _ Crypter = FacadeCrypter{}

func (FacadeCrypter) Encrypt(value string) (string, error) {
	return facades.Crypt().EncryptString(value)
}

func (FacadeCrypter) Decrypt(payload string) (string, error) {
	return facades.Crypt().DecryptString(payload)
}
