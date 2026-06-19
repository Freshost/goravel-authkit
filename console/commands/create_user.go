// Package commands holds the goravel-auth artisan commands.
package commands

import (
	"context"
	"errors"

	"github.com/goravel/framework/contracts/console"
	"github.com/goravel/framework/contracts/console/command"
	"github.com/goravel/framework/facades"
	"github.com/spf13/cast"

	"github.com/freshost/goravel-auth/repositories"
	"github.com/freshost/goravel-auth/services"
)

// CreateUser bootstraps a user (the first admin). Idempotent: re-running with an
// existing email is a no-op.
type CreateUser struct{}

// NewCreateUser returns the auth:create-user command.
func NewCreateUser() *CreateUser { return &CreateUser{} }

func (r *CreateUser) Signature() string {
	return "auth:create-user"
}

func (r *CreateUser) Description() string {
	return "Create a user / the first admin (idempotent)."
}

func (r *CreateUser) Extend() command.Extend {
	return command.Extend{
		Category: "auth",
		Flags: []command.Flag{
			&command.StringFlag{Name: "email", Usage: "User email (default: ADMIN_EMAIL env)"},
			&command.StringFlag{Name: "password", Usage: "User password (default: ADMIN_PASSWORD env)"},
			&command.StringFlag{Name: "name", Value: "Administrator", Usage: "Display name"},
			&command.StringFlag{Name: "role", Value: services.DefaultRole, Usage: "Role"},
		},
	}
}

func (r *CreateUser) Handle(ctx console.Context) error {
	email := ctx.Option("email")
	if email == "" {
		email = cast.ToString(facades.Config().Env("ADMIN_EMAIL", ""))
	}
	password := ctx.Option("password")
	if password == "" {
		password = cast.ToString(facades.Config().Env("ADMIN_PASSWORD", ""))
	}
	name := ctx.Option("name")
	role := ctx.Option("role")

	if email == "" || password == "" {
		ctx.Error("email and password are required (use --email/--password or ADMIN_EMAIL/ADMIN_PASSWORD)")
		return nil
	}

	minPwLen := facades.Config().GetInt("authkit.min_password_length", services.DefaultMinPasswordLength)
	svc := services.NewUsers(repositories.NewUsers(), services.NewFacadeHasher(), minPwLen)

	user, err := svc.Create(context.Background(), email, name, password, role)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrAlreadyExists):
			ctx.Info("User already exists, nothing to do: " + email)
			return nil
		case errors.Is(err, services.ErrValidation):
			ctx.Error("validation failed: check email and password length")
			return nil
		default:
			ctx.Error("failed to create user: " + err.Error())
			return err
		}
	}

	ctx.Info("Created user " + user.Email + " (" + user.ID.String() + ")")
	return nil
}
