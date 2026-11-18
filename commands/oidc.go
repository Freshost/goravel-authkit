package commands

import (
	"context"
	"encoding/json"
	"errors"
	"os"

	"github.com/freshost/goravel-authkit/oidc"
	"github.com/freshost/goravel-authkit/routes"
	"github.com/goravel/framework/contracts/console"
	"github.com/goravel/framework/contracts/console/command"
)

type ManageOIDCClient struct{}

func NewManageOIDCClient() *ManageOIDCClient  { return &ManageOIDCClient{} }
func (*ManageOIDCClient) Signature() string   { return "auth:oidc-client" }
func (*ManageOIDCClient) Description() string { return "Register, update or disable an OIDC client." }
func (*ManageOIDCClient) Extend() command.Extend {
	return command.Extend{Category: "auth", Flags: []command.Flag{&command.StringFlag{Name: "file", Usage: "Path to client metadata JSON"}, &command.StringFlag{Name: "disable", Usage: "Client ID to disable"}}}
}
func (*ManageOIDCClient) Handle(ctx console.Context) error {
	p, err := routes.NewOIDCProvider()
	if err != nil {
		return err
	}
	if p == nil {
		return errors.New("OIDC provider is disabled")
	}
	file, id := ctx.Option("file"), ctx.Option("disable")
	if (file == "") == (id == "") {
		return errors.New("specify exactly one of --file or --disable")
	}
	if id != "" {
		if err = p.Service.DisableClient(context.Background(), id); err != nil {
			return err
		}
		ctx.Info("OIDC client disabled.")
		return nil
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return errors.New("unable to read client metadata")
	}
	if len(data) > 64<<10 {
		return errors.New("client metadata is too large")
	}
	var client oidc.Client
	if err = json.Unmarshal(data, &client); err != nil {
		return errors.New("invalid client metadata JSON")
	}
	secret := ""
	if client.AuthMethod == "client_secret_basic" || client.AuthMethod == "client_secret_post" {
		secret = os.Getenv("AUTHKIT_OIDC_CLIENT_SECRET")
	}
	if err = p.Service.RegisterClient(context.Background(), client, secret); err != nil {
		return err
	}
	ctx.Info("OIDC client registered; previous grants for this client are invalidated.")
	return nil
}

type PruneOIDC struct{}

func NewPruneOIDC() *PruneOIDC       { return &PruneOIDC{} }
func (*PruneOIDC) Signature() string { return "auth:prune-oidc" }
func (*PruneOIDC) Description() string {
	return "Delete expired OIDC grants and replay records after retention."
}
func (*PruneOIDC) Extend() command.Extend { return command.Extend{Category: "auth"} }
func (*PruneOIDC) Handle(ctx console.Context) error {
	p, err := routes.NewOIDCProvider()
	if err != nil {
		return err
	}
	if p == nil {
		return nil
	}
	if err = p.Service.Prune(context.Background()); err != nil {
		return err
	}
	ctx.Info("Expired OIDC records pruned.")
	return nil
}
