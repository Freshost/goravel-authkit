package commands

import (
	"context"

	"github.com/goravel/framework/contracts/console"
	"github.com/goravel/framework/contracts/console/command"

	"github.com/freshost/goravel-authkit/repositories"
	"github.com/freshost/goravel-authkit/services"
)

// PruneRememberTokens deletes expired "remember me" tokens. Run it periodically
// (e.g. a daily scheduled task) so abandoned cookies don't accumulate, since
// expired rows are otherwise only cleaned up lazily when their selector is
// presented again.
type PruneRememberTokens struct{}

// NewPruneRememberTokens returns the auth:prune-remember-tokens command.
func NewPruneRememberTokens() *PruneRememberTokens { return &PruneRememberTokens{} }

func (r *PruneRememberTokens) Signature() string {
	return "auth:prune-remember-tokens"
}

func (r *PruneRememberTokens) Description() string {
	return "Delete expired remember-me tokens."
}

func (r *PruneRememberTokens) Extend() command.Extend {
	return command.Extend{Category: "auth"}
}

func (r *PruneRememberTokens) Handle(ctx console.Context) error {
	bg := context.Background()
	remember := services.NewRemember(repositories.NewRemember(), 0)
	if err := remember.PruneExpired(bg); err != nil {
		ctx.Error("Failed to prune remember tokens: " + err.Error())
		return err
	}
	sessions := services.NewSessions(repositories.NewSessions(), 0)
	if err := sessions.PruneStale(bg); err != nil {
		ctx.Error("Failed to prune stale sessions: " + err.Error())
		return err
	}
	ctx.Info("Expired remember tokens and stale sessions pruned.")
	return nil
}
