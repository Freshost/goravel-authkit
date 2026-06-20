// Package facades exposes the goravel-auth programmatic API as a Goravel facade.
// Call facades.Authkit() from app code to create users, authenticate, change
// passwords, etc. without going through the HTTP layer.
package facades

import (
	"log"

	auth "github.com/freshost/goravel-auth"
	"github.com/freshost/goravel-auth/contracts"
)

// Authkit resolves the goravel-auth service from the container.
func Authkit() contracts.Authkit {
	instance, err := auth.App.Make(auth.Binding)
	if err != nil {
		log.Fatalln(err)
		return nil
	}

	return instance.(contracts.Authkit)
}
