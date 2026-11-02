package daemon

import (
	"github.com/elchi-dev/conduit/modules/calendar"
	"github.com/elchi-dev/conduit/modules/docker"
	"github.com/elchi-dev/conduit/modules/mail"
	"github.com/elchi-dev/conduit/modules/notify"
	"github.com/elchi-dev/conduit/modules/servers"
	"github.com/elchi-dev/conduit/modules/system"
	vaultmod "github.com/elchi-dev/conduit/modules/vault"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// builtins lists the modules compiled into the daemon.
func builtins(app *App) []sdk.Module {
	if app.Notify == nil {
		app.Notify = notify.New()
	}
	return []sdk.Module{
		&vaultmod.Module{V: app.Vault},
		&system.Module{},
		servers.New(),
		docker.New(),
		mail.New(),
		calendar.New(),
		app.Notify,
	}
}

// singletons are modules with exactly one instance per daemon, keyed by the
// instance id (which equals the module id) with their display name.
var singletons = map[string]string{
	vaultmod.InstanceID: "Vault",
	system.InstanceID:   "This computer",
}
