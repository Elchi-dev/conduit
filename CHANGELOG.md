# Changelog

Newest first. Each release has full notes in `docs/releases`; this page is
the short version.

## Unreleased — 1.1.0

Ready on main. 331 built-in modules, up from 105, and money and send
actions that run exactly what you approved.
[Full notes](docs/releases/v1.1.0.md).

### Added

- **226 more modules** across smart home (Hue, Shelly, ESPHome, Zigbee2MQTT,
  Tasmota), monitoring, self-hosted platforms, backups and identity,
  business and help desks, Microsoft 365 and Google Workspace, feature
  flags, backends, wikis, project tools, cloud databases, CI servers, AI
  tools and AI spend, creators and media, clouds, home networks, home
  energy, security operations, stores, newsletters, status pages and
  on-call, 3D printers and community platforms.
- **Discord bots** read channels, reply, react, start threads, pin and
  moderate.

### Changed

- Refunds, cancellations, payments, order changes and newsletter sends take
  the values their preview showed and refuse to run if anything changed in
  between. A retried refund can't pay out twice.
- Anything that posts publicly, moves money, changes access or silences
  alerts is destructive, so it waits for your approval. A sweep of every
  action raised 27 of them because of what they do.
- Home Assistant switches locks, doors, garages, gates, alarms, cameras,
  valves and heating through its own action, with an approval and a
  preview. German device names are recognised.
- Previews and errors of sensitive actions stay private in the audit log.

### Fixed

- Actions an AI runs on your behalf, including through the daily brief, see
  exactly what you see (this is the planned 1.0.1 fix, shipped in 1.1).

## 1.0.0 (2026-11-04)

Conduit 1.0: 105 built-in modules, signed builds for every platform, and a
stable API within version 1. [Full notes](docs/releases/v1.0.0.md).

- AI that asks first: risk on every action, approvals on your phone or
  desktop, one emergency stop, and your standards handed to every AI over
  MCP.
- Full GitHub control by access token, and WireGuard networks for modules.
- A game library for ten launchers with one-click play and play time.
- A module marketplace on your hub: signed, sandboxed, rated and moderated.
- Passkeys on the daemon, and the website in German.
- APIs, the module SDK, webhooks, the CLI and the data folder stay
  compatible within version 1 ([docs/api/stability.md](docs/api/stability.md)).

## 0.3.1 (2026-11-04)

The first signed release. [Full notes](docs/releases/v0.3.1.md).

- The Android APK, desktop updates and daemon downloads are signed.
- Conduit is MIT licensed.

## 0.3.0 (2026-11-04)

Twenty-six more modules (53 in all), German, encrypted backups and two-factor
sign-in. [Full notes](docs/releases/v0.3.0.md).

- Encrypted backups, by hand or every day, restored with `conduitd restore`.
- Two-factor sign-in with any authenticator app.
- The `conduit` command-line tool.
- Signed, sandboxed modules from your hub, restricted vault folders for
  teams, home tiles, mDNS discovery, a hub operator console, container
  images and a Helm chart, and guides.

## 0.2.0 (2026-11-03)

Seven more modules (27 in all), sync between your computers, and single
sign-on. [Full notes](docs/releases/v0.2.0.md).

- Sync of the vault, agent rules and automations, end to end encrypted.
- Single sign-on with any OpenID Connect provider, the People page and
  passkeys on the hub.
- Signed webhooks, phone notifications through ntfy, password manager
  imports, one-line installers and an F-Droid repository.

## 0.1.0 (2026-11-03)

The first release. [Full notes](docs/releases/v0.1.0.md).

- The daemon with 20 built-in modules, your own modules in any language,
  MCP servers as modules, and a WebAssembly sandbox.
- Agents under rules: policies, approvals with the exact change, a
  tamper-evident audit log, undo and an emergency stop.
- Desktop apps, the Android app, the hub, the website and the developer
  API.
