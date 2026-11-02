package daemon

import (
	vaultmod "github.com/elchi-dev/conduit/modules/vault"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// builtins lists the modules compiled into the daemon.
func builtins(app *App) []sdk.Module {
	return []sdk.Module{
		&vaultmod.Module{V: app.Vault},
	}
}

// singletons are modules with exactly one instance per daemon, keyed by the
// instance id (which equals the module id) with their display name.
var singletons = map[string]string{
	vaultmod.InstanceID: "Vault",
}
