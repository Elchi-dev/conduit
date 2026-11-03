package daemon

import (
	"path/filepath"

	"github.com/elchi-dev/conduit/internal/automation"
	"github.com/elchi-dev/conduit/modules/calendar"
	"github.com/elchi-dev/conduit/modules/cloudflare"
	"github.com/elchi-dev/conduit/modules/discord"
	"github.com/elchi-dev/conduit/modules/docker"
	"github.com/elchi-dev/conduit/modules/files"
	"github.com/elchi-dev/conduit/modules/games"
	"github.com/elchi-dev/conduit/modules/github"
	"github.com/elchi-dev/conduit/modules/gitlab"
	"github.com/elchi-dev/conduit/modules/homeassistant"
	"github.com/elchi-dev/conduit/modules/mail"
	"github.com/elchi-dev/conduit/modules/metrics"
	"github.com/elchi-dev/conduit/modules/notes"
	"github.com/elchi-dev/conduit/modules/notify"
	"github.com/elchi-dev/conduit/modules/servers"
	"github.com/elchi-dev/conduit/modules/system"
	vaultmod "github.com/elchi-dev/conduit/modules/vault"
	"github.com/elchi-dev/conduit/modules/web"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// builtins lists the modules compiled into the daemon.
func builtins(app *App) []sdk.Module {
	if app.Notify == nil {
		app.Notify = notify.New()
	}
	if app.Games == nil {
		app.Games = games.New()
	}
	notesDir := ""
	if app.DataDir != "" {
		notesDir = filepath.Join(app.DataDir, "notes")
	}
	return []sdk.Module{
		&vaultmod.Module{V: app.Vault},
		&system.Module{},
		servers.New(),
		docker.New(),
		mail.New(),
		calendar.New(),
		app.Notify,
		metrics.New(),
		web.New(),
		github.New(),
		gitlab.New(),
		cloudflare.New(),
		homeassistant.New(),
		discord.New(),
		files.New(),
		app.Games,
		notes.New(notesDir),
		&automation.Module{S: app.Automations},
		&briefModule{app: app},
	}
}

// singletons are modules with exactly one instance per daemon, keyed by the
// instance id (which equals the module id) with their display name.
var singletons = map[string]string{
	vaultmod.InstanceID:   "Vault",
	system.InstanceID:     "This computer",
	automation.InstanceID: "Automations",
	briefID:               "Daily brief",
	notes.InstanceID:      "Notes",
}
