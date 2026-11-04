package daemon

import (
	"path/filepath"

	"github.com/elchi-dev/conduit/internal/automation"
	"github.com/elchi-dev/conduit/modules/adguard"
	"github.com/elchi-dev/conduit/modules/aws"
	"github.com/elchi-dev/conduit/modules/calendar"
	"github.com/elchi-dev/conduit/modules/cloudflare"
	"github.com/elchi-dev/conduit/modules/containerregistry"
	"github.com/elchi-dev/conduit/modules/database"
	"github.com/elchi-dev/conduit/modules/digitalocean"
	"github.com/elchi-dev/conduit/modules/discord"
	"github.com/elchi-dev/conduit/modules/docker"
	"github.com/elchi-dev/conduit/modules/files"
	"github.com/elchi-dev/conduit/modules/fly"
	"github.com/elchi-dev/conduit/modules/games"
	"github.com/elchi-dev/conduit/modules/gameservers"
	"github.com/elchi-dev/conduit/modules/gitea"
	"github.com/elchi-dev/conduit/modules/github"
	"github.com/elchi-dev/conduit/modules/gitlab"
	"github.com/elchi-dev/conduit/modules/hetzner"
	"github.com/elchi-dev/conduit/modules/homeassistant"
	"github.com/elchi-dev/conduit/modules/jellyfin"
	"github.com/elchi-dev/conduit/modules/jira"
	"github.com/elchi-dev/conduit/modules/kubernetes"
	"github.com/elchi-dev/conduit/modules/linear"
	"github.com/elchi-dev/conduit/modules/mail"
	"github.com/elchi-dev/conduit/modules/mastodon"
	"github.com/elchi-dev/conduit/modules/metrics"
	"github.com/elchi-dev/conduit/modules/milanote"
	"github.com/elchi-dev/conduit/modules/nextcloud"
	"github.com/elchi-dev/conduit/modules/notes"
	"github.com/elchi-dev/conduit/modules/notify"
	"github.com/elchi-dev/conduit/modules/obs"
	"github.com/elchi-dev/conduit/modules/ollama"
	"github.com/elchi-dev/conduit/modules/pagerduty"
	"github.com/elchi-dev/conduit/modules/pihole"
	"github.com/elchi-dev/conduit/modules/plex"
	"github.com/elchi-dev/conduit/modules/proxmox"
	"github.com/elchi-dev/conduit/modules/redis"
	"github.com/elchi-dev/conduit/modules/s3"
	"github.com/elchi-dev/conduit/modules/sentry"
	"github.com/elchi-dev/conduit/modules/servers"
	"github.com/elchi-dev/conduit/modules/slack"
	"github.com/elchi-dev/conduit/modules/spotify"
	"github.com/elchi-dev/conduit/modules/standards"
	"github.com/elchi-dev/conduit/modules/system"
	"github.com/elchi-dev/conduit/modules/tailscale"
	"github.com/elchi-dev/conduit/modules/truenas"
	"github.com/elchi-dev/conduit/modules/twitch"
	"github.com/elchi-dev/conduit/modules/unifi"
	"github.com/elchi-dev/conduit/modules/uptimekuma"
	vaultmod "github.com/elchi-dev/conduit/modules/vault"
	"github.com/elchi-dev/conduit/modules/vaultwarden"
	"github.com/elchi-dev/conduit/modules/vercel"
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
		if app.DataDir != "" {
			app.Games.DataDir = filepath.Join(app.DataDir, "games") // play sessions, added games, cover cache
		}
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
		func() sdk.Module { m := mail.New(); m.Dir = app.dataSub("module-data/mail"); return m }(),
		calendar.New(),
		app.Notify,
		metrics.New(),
		web.New(),
		github.New(),
		gitlab.New(),
		cloudflare.New(),
		homeassistant.New(),
		discord.New(),
		kubernetes.New(),
		proxmox.New(),
		obs.New(),
		aws.New(),
		slack.New(),
		jira.New(),
		&spotify.Module{Dir: app.dataSub("module-data/spotify")},
		gameservers.New(),
		twitch.New(),
		jellyfin.New(),
		pihole.New(),
		adguard.New(),
		truenas.New(),
		linear.New(),
		pagerduty.New(),
		sentry.New(),
		tailscale.New(),
		hetzner.New(),
		digitalocean.New(),
		vercel.New(),
		fly.New(),
		database.New(),
		redis.New(),
		uptimekuma.New(),
		unifi.New(),
		nextcloud.New(),
		ollama.New(),
		s3.New(),
		plex.New(),
		gitea.New(),
		mastodon.New(),
		vaultwarden.New(),
		containerregistry.New(),
		milanote.New(),
		files.New(),
		app.Games,
		notes.New(notesDir),
		standards.New(app.dataSub("standards")),
		&automation.Module{S: app.Automations},
		&briefModule{app: app},
		app.ambient(),
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
	standards.InstanceID:  "Standards",
	ambientID:             "Ambient status",
}

// ambient returns the app's ambient status module, creating it once.
func (a *App) ambient() *ambientModule {
	if a.Server.Ambient == nil {
		a.Server.Ambient = &ambientModule{app: a}
	}
	return a.Server.Ambient
}
