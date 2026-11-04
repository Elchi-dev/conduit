# Conduit

One control plane for everything you run: mail, secrets, servers, containers,
dashboards, local processes, games and anything else a module can reach. AI
agents can drive all of it, under rules you set.

> **Status:** v0.1.0, the first release ([notes](docs/releases/v0.1.0.md)).
> See [BUILD_LOG.md](BUILD_LOG.md) for how it was built and
> [CONTEXT.md](CONTEXT.md) for the current state.

## What's in it

- **316 modules**: vault, this computer, servers over SSH, Docker, mail,
  calendar, notifications (ntfy, Telegram, Discord, Slack, Matrix, Gotify,
  email), Prometheus, Grafana, uptime checks, Uptime Kuma, UptimeRobot, Healthchecks.io, Better Stack Uptime, Netdata, Zabbix, Alertmanager, Loki, Beszel, Checkmk, Gatus, GitHub,
  GitLab, Gitea and Forgejo, Bitbucket, Azure DevOps, Woodpecker CI, Jenkins, container registries, Cloudflare (DNS and tunnels), Kubernetes, Argo CD, Argo Workflows, HCP Terraform, Nomad, Consul, HashiCorp Vault and OpenBao, 1Password Connect, Bitwarden Secrets Manager, Infisical, Doppler, SOPS-encrypted files, Harbor, SonarQube and SonarCloud, CircleCI, Buildkite, TeamCity, GoCD, Concourse, Codecov, Snyk, DefectDojo, Dependency-Track, GitGuardian, Semgrep, Sourcegraph, Drone CI, Portainer, Proxmox VE, Proxmox Backup Server, Xen Orchestra, Incus, TrueNAS, Unraid, Synology DSM, Scrutiny, Network UPS Tools, OPNsense, CrowdSec, Wazuh, MikroTik RouterOS, OpenWrt, FRITZ!Box, TP-Link Omada, ntopng, LibreNMS, NetBox, AWS, S3 storage, Backblaze B2, restic repositories, Kopia, rclone, Hetzner Cloud,
  DigitalOcean, Linode, Vultr, Scaleway, UpCloud, Azure, Google Cloud, OVHcloud, IONOS Cloud, Vercel, Netlify, Fly.io, Render, Railway, Neon, Turso, Upstash, PlanetScale, Coolify, Dokploy, CapRover, Supabase, PocketBase, Appwrite, Directus, Strapi, NocoDB, PostgreSQL and MySQL, Redis, MongoDB, ClickHouse, InfluxDB, Elasticsearch and OpenSearch, Meilisearch, Tailscale, Headscale, NetBird, wg-easy, Syncthing, Speedtest Tracker,
  UniFi, Sentry, Datadog, PagerDuty, Opsgenie, incident.io, Statuspage, Instatus, Plausible Analytics, Umami, Google Analytics, Google Search Console, Matomo, Fathom Analytics, PostHog, Unleash, Flagsmith, LaunchDarkly, GrowthBook, Stripe, Lemon Squeezy, Paddle, Shopify, WooCommerce, BigCommerce, Gumroad, Printful, HubSpot, Twilio, Cal.com, listmonk, Resend, Mailgun, SendGrid, Postmark, Mailchimp, Brevo, Kit, Buttondown, Zendesk, Freshdesk, Chatwoot, Zammad, Intercom, Crisp, Help Scout, FreeScout, Ghost, Microsoft 365, Google Workspace, Fastmail, Dropbox, Slack, Mattermost, Jira, Linear, YouTrack, Plane, Asana, ClickUp, monday.com, Todoist, Vikunja, Trello, Notion, Outline, BookStack, Nextcloud, Seafile, File Browser, ownCloud Infinite Scale, Milanote, Paperless-ngx, Karakeep, linkding, wallabag, Miniflux, FreshRSS, Firefly III, Ghostfolio, Invoice Ninja, Kimai, WakaTime, Mealie, Grocy, Homebox, Monica, n8n, Home Assistant, MQTT brokers, Zigbee2MQTT, Philips Hue, Shelly, ESPHome, Tasmota, Homebridge, HomeWizard Energy, Tibber, SolarEdge, Victron VRM, Node-RED, OctoPrint, Moonraker (Klipper),
  Pi-hole, AdGuard Home, Technitium DNS, PowerDNS, Porkbun, Nginx Proxy Manager, Traefik, Caddy, authentik, Keycloak, Zitadel, Okta, Auth0, Kanidm, LLDAP, Vaultwarden, Jellyfin, Plex, Tautulli, Overseerr and Jellyseerr, Kodi, VLC, Navidrome and Subsonic servers, Audiobookshelf, Komga, Kavita, Calibre-Web, RomM, Immich, PhotoPrism, Frigate, Sonarr, Radarr, Lidarr, Readarr and Prowlarr, Bazarr, qBittorrent, Transmission, Deluge, SABnzbd, NZBGet, Ollama, OpenAI-compatible servers (LM Studio, LocalAI, vLLM, llama.cpp, Jan), LiteLLM, OpenRouter, Anthropic, OpenAI, Mistral AI, Groq, ComfyUI, Hugging Face, Replicate, RunPod, Vast.ai, ElevenLabs, Discord, Telegram, Signal, Matrix, Rocket.Chat, Zulip, Nextcloud Talk, Gotify, Discourse, Mastodon, Bluesky, Lemmy, Twitch, Kick, YouTube, OBS Studio, StreamElements, Streamer.bot,
  Spotify, game servers (Minecraft, Source), Pterodactyl and Pelican, Crafty Controller, AMP, Steam and Xbox (OpenXBL) accounts, BattleMetrics, FACEIT, Lichess, Chess.com, files and backups, a game
  library (Steam, Epic, GOG, Riot, Battle.net, EA, Ubisoft, Xbox, itch.io, Lutris), AI standards and toolkits, notes, weather (Open-Meteo), automations, the daily brief and ambient status. Any MCP
  server mounts as a module; write your own in any language
  ([kits](sdk/external/)) or run untrusted ones in a WebAssembly sandbox.
- **Agents under rules**: the built-in assistant, any MCP client, local
  models or API keys. Policies per agent, system and action; approvals with
  exact previews; a tamper-evident audit log; undo; an emergency stop.
- **Everywhere**: a desktop app with a tray, an Android app that pairs by QR
  code (and confirms approvals with your fingerprint), remote access through
  any hub with end-to-end encryption, or directly on your network.
- **Signed updates** for the desktop app, the daemon (with automatic
  rollback) and the hub.

## How it fits together

Conduit works the way git and GitHub do. The protocol is open, a default hub
is provided, and every install chooses:

- **Local only** — the daemon runs on your machine, nothing leaves it.
- **Default hub** — accounts, device pairing, an end-to-end encrypted relay to
  your phone, sync, the module registry and updates.
- **Your own hub** — run `conduit-hub` yourself; accounts and mail settings
  belong to whoever hosts it.

| Part | Path | Language |
| --- | --- | --- |
| Daemon (`conduitd`) | `cmd/conduitd`, `internal/` | Go |
| Hub (`conduit-hub`) | `cmd/conduit-hub`, `internal/hub` | Go |
| API contracts | `api/openapi` | OpenAPI 3.1 |
| Module SDK and kits | `pkg/sdk`, `sdk/external` | Go, Python, TypeScript, any language over JSON-RPC |
| API clients | `sdk/clients` | TypeScript, Python |
| Built-in modules | `modules/` | Go |
| App UI | `web/` | TypeScript, React |
| Desktop and Android shell | `apps/desktop` | Tauri 2 (Rust) |
| Public website | `site/` | Astro |
| Documentation | `docs/` | Markdown |

## Install

Desktop and Android apps are on the
[releases page](https://github.com/Elchi-dev/conduit/releases). For the daemon
or a hub on a server:

```sh
curl -fsSL https://<your hub>/install.sh | sh          # Linux, macOS
irm https://<your hub>/install.ps1 | iex               # Windows PowerShell
```

The scripts check every download against the release's checksums. Options,
services and uninstalling: [docs/install.md](docs/install.md). The
command-line client installs with `--cli`: [docs/cli.md](docs/cli.md).
Container images: `ghcr.io/elchi-dev/conduitd` and `ghcr.io/elchi-dev/conduit-hub`,
plus a Helm chart for the hub in `deploy/helm`.

## Build from source

Requirements: Go 1.26+, Node 22 with pnpm 10, and for the desktop shell Rust
stable plus the [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/).

```sh
make build      # web UI, bin/conduitd, bin/conduit-hub
make test
./bin/conduitd  # http://127.0.0.1:7600
```

During UI work run `cd web && pnpm dev`; it proxies `/api` to the daemon.

## Documentation

- [Architecture](docs/architecture/README.md) and [decision records](docs/architecture/adr/)
- [Protocol](docs/protocol/README.md)
- [API](docs/api/README.md)
- [Modules](docs/modules/README.md)
- [Self-hosting a hub](docs/self-hosting/README.md)
- The same docs are on every hub's website (`site/`).

## License

MIT. See [LICENSE](LICENSE).
