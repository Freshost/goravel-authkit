// Command setup implements `./artisan package:install
// github.com/freshost/goravel-auth`. It registers auth.ServiceProvider into the
// consuming app and writes the package's config files. The provider itself then
// registers the migrations, routes, and artisan commands at boot — so install
// is a single step.
package main

import (
	"os"

	"github.com/goravel/framework/packages"
	"github.com/goravel/framework/packages/modify"
	"github.com/goravel/framework/support/file"
	"github.com/goravel/framework/support/path"
)

func main() {
	setup := packages.Setup(os.Args)
	module := setup.Paths().Module().String()

	authConfig, err := file.GetPackageContent(module, "setup/config/auth.go")
	if err != nil {
		panic(err)
	}
	authkitConfig, err := file.GetPackageContent(module, "setup/config/authkit.go")
	if err != nil {
		panic(err)
	}
	hashingConfig, err := file.GetPackageContent(module, "setup/config/hashing.go")
	if err != nil {
		panic(err)
	}

	moduleImport := setup.Paths().Module().Import()
	serviceProvider := "&auth.ServiceProvider{}"

	setup.Install(
		modify.RegisterProvider(moduleImport, serviceProvider),
		modify.File(path.Config("auth.go")).Overwrite(authConfig),
		modify.File(path.Config("authkit.go")).Overwrite(authkitConfig),
		modify.File(path.Config("hashing.go")).Overwrite(hashingConfig),
	).Uninstall(
		// Only remove the package-specific config; leave auth.go/hashing.go in
		// place (the app needs working auth + hashing config regardless).
		modify.File(path.Config("authkit.go")).Remove(),
		modify.UnregisterProvider(moduleImport, serviceProvider),
	).Execute()
}
