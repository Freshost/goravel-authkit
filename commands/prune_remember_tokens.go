package commands

import (
	"context"
	"time"

	"github.com/goravel/framework/contracts/console"
	"github.com/goravel/framework/contracts/console/command"
	"github.com/goravel/framework/facades"

	"github.com/freshost/goravel-authkit/repositories"
	"github.com/freshost/goravel-authkit/services"
)

// PruneRememberTokens deletes expired "remember me" tokens. Run it periodically
// (e.g. a daily scheduled task) so abandoned cookies don't accumulate, since
// expired rows are otherwise only cleaned up lazily when their selector is
// presented again.
type PruneTables struct{ Remember, Sessions string }
type PruneRememberTokens struct{ tables []PruneTables }

// NewPruneRememberTokens returns the auth:prune-remember-tokens command.
func NewPruneRememberTokens(tables ...PruneTables) *PruneRememberTokens {
	if len(tables) == 0 {
		tables = []PruneTables{{}}
	}
	return &PruneRememberTokens{tables: tables}
}

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
	lifetime := time.Duration(facades.Config().GetInt("session.lifetime", 120)) * time.Minute
	seen := map[PruneTables]bool{}
	for _, tables := range r.tables {
		if seen[tables] {
			continue
		}
		seen[tables] = true
		remember := services.NewRemember(repositories.NewRememberWithTable(tables.Remember), 0)
		if err := remember.PruneExpired(bg); err != nil {
			return err
		}
		sessions := services.NewSessions(repositories.NewSessionsWithTable(tables.Sessions, tables.Remember), lifetime)
		if err := sessions.PruneStale(bg); err != nil {
			return err
		}
	}
	ctx.Info("Expired remember tokens and stale sessions pruned.")
	return nil
}
