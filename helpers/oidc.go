package helpers

import (
	contractshttp "github.com/goravel/framework/contracts/http"
	"slices"
)

const (
	CtxOIDCClientID     = "auth_oidc_client_id"
	CtxOIDCConnectionID = "auth_oidc_connection_id"
	CtxOIDCScopes       = "auth_oidc_scopes"
)

func OIDCClientID(ctx contractshttp.Context) string {
	v, _ := ctx.Value(CtxOIDCClientID).(string)
	return v
}
func OIDCConnectionID(ctx contractshttp.Context) string {
	v, _ := ctx.Value(CtxOIDCConnectionID).(string)
	return v
}
func OIDCScopes(ctx contractshttp.Context) []string {
	v, _ := ctx.Value(CtxOIDCScopes).([]string)
	return slices.Clone(v)
}
