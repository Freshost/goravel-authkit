// Command setup implements `./artisan package:install
// github.com/freshost/goravel-auth`. It registers auth.ServiceProvider into the
// consuming app's provider list (app.go or bootstrap/providers.go). Route and
// migration wiring stays explicit in the app (see the package README).
package main

import (
	"os"

	"github.com/goravel/framework/packages"
	"github.com/goravel/framework/packages/match"
	"github.com/goravel/framework/packages/modify"
	"github.com/goravel/framework/support/env"
	"github.com/goravel/framework/support/path"
)

func main() {
	setup := packages.Setup(os.Args)

	appConfigPath := path.Config("app.go")
	moduleImport := setup.Paths().Module().Import()
	serviceProvider := "&auth.ServiceProvider{}"

	setup.Install(
		// Add the service provider to app.go (classic setup) ...
		modify.When(func(_ map[string]any) bool {
			return !env.IsBootstrapSetup()
		}, modify.GoFile(appConfigPath).
			Find(match.Imports()).Modify(modify.AddImport(moduleImport)).
			Find(match.Providers()).Modify(modify.Register(serviceProvider))),

		// ... or to bootstrap/providers.go (bootstrap setup).
		modify.When(func(_ map[string]any) bool {
			return env.IsBootstrapSetup()
		}, modify.RegisterProvider(moduleImport, serviceProvider)),
	).Uninstall(
		modify.When(func(_ map[string]any) bool {
			return !env.IsBootstrapSetup()
		}, modify.GoFile(appConfigPath).
			Find(match.Providers()).Modify(modify.Unregister(serviceProvider)).
			Find(match.Imports()).Modify(modify.RemoveImport(moduleImport))),

		modify.When(func(_ map[string]any) bool {
			return env.IsBootstrapSetup()
		}, modify.UnregisterProvider(moduleImport, serviceProvider)),
	).Execute()
}
