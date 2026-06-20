// Command setup implements `./artisan package:install
// github.com/freshost/goravel-auth`. It:
//   - registers auth.ServiceProvider into the app,
//   - writes config/authkit.go (the package's own settings file),
//   - injects the session "admin" guard + "users" orm provider into the app's
//     EXISTING config/auth.go (additively — it does not clobber other guards),
//   - sets bcrypt cost 12 in the app's EXISTING config/hashing.go.
//
// The provider then registers the migrations, routes, and commands at boot, so
// install is a single step.
package main

import (
	"os"

	"github.com/goravel/framework/packages"
	"github.com/goravel/framework/packages/match"
	"github.com/goravel/framework/packages/modify"
	"github.com/goravel/framework/support/file"
	"github.com/goravel/framework/support/path"
)

func main() {
	setup := packages.Setup(os.Args)
	module := setup.Paths().Module().String()

	authkitConfig, err := file.GetPackageContent(module, "setup/config/authkit.go")
	if err != nil {
		panic(err)
	}

	moduleImport := setup.Paths().Module().Import()
	serviceProvider := "&auth.ServiceProvider{}"

	authConfigPath := path.Config("auth.go")
	hashingConfigPath := path.Config("hashing.go")

	// The session guard + orm provider goravel-auth needs, as Go source.
	guard := `map[string]any{
		"driver":   "session",
		"provider": "users",
	}`
	provider := `map[string]any{
		"driver": "orm",
	}`

	setup.Install(
		// Register the provider in bootstrap/providers.go.
		modify.RegisterProvider(moduleImport, serviceProvider),

		// Write our own config file (safe to (over)write — it is package-owned).
		modify.File(path.Config("authkit.go")).Overwrite(authkitConfig),

		// Add the "admin" session guard + "users" orm provider to the existing
		// config/auth.go WITHOUT touching the app's other guards/providers.
		modify.WhenFileExists(authConfigPath, modify.GoFile(authConfigPath).
			Find(match.Config("auth.guards")).Modify(modify.AddConfig("admin", guard)).
			Find(match.Config("auth.providers")).Modify(modify.AddConfig("users", provider))),

		// Ensure bcrypt cost 12 in the existing config/hashing.go.
		modify.WhenFileExists(hashingConfigPath, modify.GoFile(hashingConfigPath).
			Find(match.Config("hashing.bcrypt")).Modify(modify.AddConfig("rounds", "12"))),
	).Uninstall(
		modify.File(path.Config("authkit.go")).Remove(),

		modify.WhenFileExists(authConfigPath, modify.GoFile(authConfigPath).
			Find(match.Config("auth.guards")).Modify(modify.RemoveConfig("admin")).
			Find(match.Config("auth.providers")).Modify(modify.RemoveConfig("users"))),

		modify.UnregisterProvider(moduleImport, serviceProvider),
	).Execute()
}
