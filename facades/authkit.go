// Package facades exposes the goravel-authkit programmatic API as a Goravel facade.
// Call facades.Authkit() from app code to create users, authenticate, change
// passwords, etc. without going through the HTTP layer.
package facades

import (
	"log"

	authkit "github.com/freshost/goravel-authkit"
	"github.com/freshost/goravel-authkit/contracts"
)

// Authkit resolves the goravel-authkit service from the container.
func Authkit() contracts.Authkit {
	instance, err := authkit.App.Make(authkit.Binding)
	if err != nil {
		log.Fatalln(err)
		return nil
	}

	return instance.(contracts.Authkit)
}
