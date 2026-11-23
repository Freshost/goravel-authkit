package routes

import (
	"testing"

	frameworkconfig "github.com/goravel/framework/config"
	"github.com/goravel/framework/contracts/binding"
	"github.com/goravel/framework/foundation"
	"github.com/stretchr/testify/require"
)

func TestOIDCConsentTemplateConfig(t *testing.T) {
	t.Setenv("APP_KEY", "01234567890123456789012345678901")
	cfg := frameworkconfig.NewApplication("")
	app := &foundation.Application{Container: foundation.NewContainer()}
	app.Instance(binding.Config, cfg)
	previous := foundation.App
	foundation.App = app
	t.Cleanup(func() { foundation.App = previous })

	provider := map[string]any{"enabled": true}
	cfg.Add("authkit", map[string]any{"oidc": map[string]any{"provider": provider}})
	require.Empty(t, OIDCProviderConfig().ConsentTemplate)
	source := "<h1>{{.ClientName}}</h1>\n<p>{{.Account}}</p>"
	cfg.Add("authkit.oidc.provider", map[string]any{"enabled": true, "consent_template": source})
	require.Equal(t, source, OIDCProviderConfig().ConsentTemplate)
}
