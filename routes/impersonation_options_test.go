package routes

import (
	"testing"

	frameworkconfig "github.com/goravel/framework/config"
	"github.com/goravel/framework/contracts/binding"
	"github.com/goravel/framework/foundation"
	"github.com/stretchr/testify/require"
)

func TestImpersonationActionPolicyConfig(t *testing.T) {
	t.Setenv("APP_KEY", "01234567890123456789012345678901")
	for _, tc := range []struct {
		name       string
		global     map[string]any
		guard      map[string]any
		wantGlobal bool
		wantGuard  bool
	}{
		{name: "existing default"},
		{name: "global delegation inherited", global: map[string]any{"allow_sensitive_actions": true}, wantGlobal: true, wantGuard: true},
		{name: "guard opts in", guard: map[string]any{"allow_sensitive_actions": true}, wantGuard: true},
		{name: "guard opts out", global: map[string]any{"allow_sensitive_actions": true}, guard: map[string]any{"allow_sensitive_actions": false}, wantGlobal: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := frameworkconfig.NewApplication("")
			cfg.Add("authkit", map[string]any{
				"impersonation": tc.global,
				"guards":        map[string]any{"client": map[string]any{"impersonation": tc.guard}},
			})
			app := &foundation.Application{Container: foundation.NewContainer()}
			app.Instance(binding.Config, cfg)
			previous := foundation.App
			foundation.App = app
			t.Cleanup(func() { foundation.App = previous })

			require.Equal(t, tc.wantGlobal, OptionsFromConfig().ImpersonationAllowSensitiveActions)
			require.Equal(t, tc.wantGuard, OptionsForGuard("client").ImpersonationAllowSensitiveActions)
		})
	}
}
