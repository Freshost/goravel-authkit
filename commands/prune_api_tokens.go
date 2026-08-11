package commands

import (
	"context"
	"slices"

	"github.com/goravel/framework/contracts/console"
	"github.com/goravel/framework/contracts/console/command"

	"github.com/freshost/goravel-authkit/repositories"
	"github.com/freshost/goravel-authkit/services"
)

// PruneAPITokens removes tokens that expired or were revoked more than the
// service retention period ago from every configured guard table.
type PruneAPITokens struct{ tables []string }

func NewPruneAPITokens(tables ...string) *PruneAPITokens {
	return &PruneAPITokens{tables: slices.Clone(tables)}
}

func (r *PruneAPITokens) Signature() string { return "auth:prune-api-tokens" }

func (r *PruneAPITokens) Description() string { return "Delete old expired and revoked API tokens." }

func (r *PruneAPITokens) Extend() command.Extend { return command.Extend{Category: "auth"} }

func (r *PruneAPITokens) Handle(ctx console.Context) error {
	seen := make(map[string]struct{}, len(r.tables))
	for _, table := range r.tables {
		if table == "" {
			table = repositories.DefaultAPITokensTable
		}
		if _, ok := seen[table]; ok {
			continue
		}
		seen[table] = struct{}{}
		tokens := services.NewAPITokens(repositories.NewAPITokensWithTable(table), nil, nil, nil, nil, 0, 0)
		if err := tokens.Prune(context.Background()); err != nil {
			ctx.Error("Failed to prune API tokens: " + err.Error())
			return err
		}
	}
	ctx.Info("Old API tokens pruned.")
	return nil
}
