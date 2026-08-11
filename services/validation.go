package services

import (
	"errors"
	"net/mail"
	"strings"
)

const maxEmailBytes = 254

// validateEmail enforces the canonical email format at the service boundary so
// HTTP, Artisan, jobs, and direct package callers all receive the same rules.
func validateEmail(email string) error {
	if email == "" {
		return errors.Join(ErrValidation, errors.New("email is required"))
	}
	if len(email) > maxEmailBytes || strings.ContainsAny(email, "\r\n") {
		return errors.Join(ErrValidation, errors.New("email is invalid"))
	}

	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email {
		return errors.Join(ErrValidation, errors.New("email is invalid"))
	}

	return nil
}
