# Build log

Newest first. One entry per phase: what landed, what changed from the plan,
and why.

## 2026-11-04 · Phases 34–38 — Signed releases, owner requests, fourth review

- **Phase 34, releases:** v0.3.0 (all platforms, macOS runners back) and
  v0.3.1, the first signed release: checksums, desktop updates and the
  Android APK are signed with the owner's keys (stored as secrets on 4 Nov).
  The F-Droid step needs a repository address ending in `/repo`, which
  release downloads can't give; it no longer fails releases. Upgrade test
  from every release and a load test run in CI. API stability promise
  (`docs/api/stability.md`). MIT license.
- **Phase 35, owner requests:** marketplace (listings, install counts,
  ratings, reviews, reports, moderation, advisories), a game library across
  ten launchers with play tracking, the standards module for AI (MCP
  resources and prompts), Milanote, Proton Mail Bridge with full mailbox
  management, Spotify listening history and playback (after Spotify's
  February 2026 API changes), GitHub with most of its REST API by token,
  and WireGuard networks that module instances can use.
- **Phase 36, fourth security review** of everything since v0.3.0. Fixed:
  a GraphQL mutation hidden in comments passed the read-only check (now a
  real parser); raw GitHub writes reached destructive operations (now
  destructive); custom games could run any command at write risk (programs
  now destructive, launch links allow-listed); cover downloads could be
  redirected to internal addresses (`internal/netguard`: public addresses
  only, checked at connect time); mail attachment types could inject
  headers; install pings could inflate counts (capped per source, IPv6 by
  /64); re-pinning the mail certificate is destructive; registry icon ids
  from a hub are checked.
- **Not done:** daemon passkeys (the helper was stopped).

## 2026-11-04 · Phases 31–33 — German, six modules, third review

- **Phase 31, German:** every string in the web app goes through `t()` /
  `tn()` (`web/src/i18n`); the German dictionary covers all 704 strings
  with a glossary at its top (Freigabe, Notstopp, Verlauf, Tresor…, informal
  "du"). The language follows the browser until chosen in Settings,
  Appearance; dates and numbers use `Intl`. `pnpm test:i18n` (in CI) fails
  on a missing entry or mismatched placeholders; e2e covers switching and a
  German browser. What the daemon sends (module and action names, errors)
  stays English (`docs/architecture/web.md`).
- **Phase 32, modules (53):** S3-compatible storage (MinIO, R2, Garage;
  path-style by default, presigned links), Plex, Gitea and Forgejo (issues,
  comments and merges with undo), Mastodon, Vaultwarden (counts only, never
  names) and container registries (Docker Hub, GHCR, Quay, Harbor; the
  Bearer token flow; tag-list paging stays on the same repository).
- **Phase 33, third security review:** an independent review of everything
  since v0.2.0. Fixed:
  - restricted vault folders: a JSON-escaped `secret:\/\/…` reference got
    past the settings check (now done on the decoded settings, the way the
    engine resolves them); `import_env` without a prefix could overwrite a
    restricted secret (each name is now checked, and keys can't pick a
    folder); leak scans could confirm guesses and any admin could sync the
    whole vault to their own daemon (both now need access to every
    restricted folder; only the owner syncs the vault while folders are
    restricted); automations reach a folder only if their last editor may;
  - home tiles are set by people only, not keys;
  - the hub keeps deleted accounts' author handles as tombstones and
    reserves `mcp` and similar handles; daemons refuse `mcp-` ids, module
    downgrades and redirects away from https, and serialise installs;
  - modules: Source RCON `say` refused `;` (it ran console commands), the
    database query check matches across whitespace and denies session-
    killing and query-from-string functions, header credentials don't
    follow redirects to another host, Redis replies have a byte budget;
  - mDNS answers no longer amplify (questions capped and deduplicated, not
    echoed, unicast only on-link); the CLI strips terminal escapes from
    module output; release workflow actions pinned.
  - Documented rather than changed: backups contain the two-factor and
    relay keys (the backup passphrase protects them).

## 2026-11-04 · Phases 28–30 — Tests, registry, team vault, more modules

- **Phase 28, browser tests:** 31 Playwright tests drive a freshly built
  daemon through first run, the command bar, modules, the vault, API keys,
  agent rules, People, Settings, sign-in and the emergency stop, at desktop
  and phone widths, using roles and labels only. An axe scan of the main
  screens in dark and light fails CI on serious or critical WCAG 2.1 A/AA
  problems; it found low-contrast muted, fault, ok and (light) amber
  colours and unnamed meters, all fixed. New CI jobs: `e2e`, and
  `databases` (real PostgreSQL 16 and MySQL 8.4 for the database module).
- **Phase 29, modules from a hub:** Modules, Add modules from your hub
  browses the linked hub's registry and installs sandboxed (WebAssembly)
  builds: the author's signature and the download's checksum are checked,
  the author key is pinned on first install, the person sees the key
  fingerprint and the network hosts first, and a module must use ids in
  its author's namespace (`docs/protocol/sandbox.md`).
- **Phase 30, team vault and modules:** the owner can restrict vault
  folders (`finance/`, `prod/`) to roles and people, enforced by an engine
  guard for every caller and in every setting that takes a secret
  reference (`docs/architecture/vault.md`). Ten more modules, 47 in all:
  Hetzner Cloud, DigitalOcean, Vercel, Fly.io, PostgreSQL and MySQL
  (read-only queries in a read-only transaction), Redis and Valkey (a
  small RESP client), Uptime Kuma, UniFi, Nextcloud, Ollama; and Matrix,
  Gotify and email notification channels (the password is never sent
  without TLS; header injection is refused).

## 2026-11-03/04 · Phases 23–27 — Toward v0.3.0

The build keeps going until Thu 5 Nov 00:00 CET; after each phase the next
tasks come from the backlog in CONTEXT.md.

- **Phase 23, modules (37 in all):** game servers (Minecraft server list
  ping and RCON, Source A2S queries with the challenge handshake and RCON,
  tested against fakes that speak the real wire formats), Twitch, Jellyfin,
  Pi-hole v6, AdGuard Home, TrueNAS SCALE (certificate pinning), Linear
  (GraphQL), PagerDuty (REST and Events v2), Sentry and Tailscale (API key
  or OAuth client, key-expiry warnings).
- **Phase 24, backups** (`docs/backup.md`): one encrypted file with a
  consistent database snapshot and the data folder; Argon2id and
  XChaCha20-Poly1305 in 64 KiB chunks whose nonces carry the chunk number
  and a final flag, so changed, reordered or cut-off files don't restore.
  Download from Settings, a daily schedule to a folder with the passphrase in
  the vault, and `conduitd backup` / `conduitd restore`.
- **Phase 25, two-factor sign-in** on daemon and hub: authenticator codes
  (RFC 6238, each code works once) and single-use recovery codes; setup
  needs the password; admins can reset it for others; SSO and passkeys
  are exempt; a hub password reset keeps two-factor on.
- **Phase 26, the `conduit` CLI** (`docs/cli.md`): login with an API key,
  modules, run actions with `key=value` input, approvals, audit, undo, the
  live event stream, vault names, emergency stop, automations, shell
  completion; exit codes for scripts; installed with `install.sh --cli`.
- **Phase 27, operators and discovery:** a hub operator console (stats,
  accounts, switch off, delete) on the hub website; daemons announce
  themselves with mDNS (`_conduit._tcp`), and Sync can find other computers
  on the network.
- **Also:** pinned live tiles on the home board (any read action of any
  system; the plan's "configurable board of live tiles"), readable action
  names in the activity list, and guides for developers, gamers, homelabs
  and teams (`docs/guides/`).

## 2026-11-03 · Phase 22 — Release v0.2.0

**Landed**

- v0.2.0 is published: https://github.com/Elchi-dev/conduit/releases/tag/v0.2.0
  (17 assets): daemon and hub binaries for six platforms with `SHA256SUMS`,
  the Linux desktop packages (deb, rpm, AppImage) and the Android APK.
  Release notes in `docs/releases/v0.2.0.md`.

**Changed from the plan**

- No macOS or Windows desktop installers in v0.2.0. Since the afternoon,
  macOS jobs sit queued for 15 minutes without a runner and are cancelled
  (probably the private repository's Actions minutes; macOS counts ten
  times). The Windows desktop build stopped after 58 minutes with its log
  gone. v0.1.0's installers still work, and the daemon and hub binaries for
  both systems are in v0.2.0. The release workflow now caches Rust builds
  and gives desktop jobs two hours; re-running the failed jobs of the
  v0.2.0 run (Actions, release, Re-run failed jobs) adds the installers.

## 2026-11-03 · Phase 21 — Second security review

A second independent reviewer (a separate agent that hadn't seen the work)
went through everything added since v0.1.0 and proved two findings with
tests. All confirmed findings are fixed:

1. **High: single sign-on matched accounts by email alone**, owners
   included, so anyone who could make the provider send the owner's address
   got an owner session. Accounts now follow the provider's stable `sub`
   (`oidc_links`); owners and admins are never linked by email and link
   their identity themselves while signed in (Settings, Single sign-on);
   a linked account can't gain a second identity; at least one allowed
   domain is required; `email_verified` must be the JSON value `true`.
2. **Medium: sync replays brought deleted items back** after the 90-day
   tombstone expiry, through a recorded LAN request or a stale hub blob.
   Tombstones are now kept for good, and the peer endpoint refuses
   documents sealed more than 15 minutes ago.
3. **Medium: a hub passkey outlived a password reset**, and adding one
   needed only a session. Adding one now needs the password; a reset
   removes every passkey.
4. **Low: the unauthenticated sync endpoint could hold gigabytes** in
   flight. Bodies are capped at 8 MiB, two exchanges run at a time, IPv6
   sources are limited per /64 (sign-ins too), and callers learn nothing
   until their document decrypts.
5. **Low: installers checked integrity, not authenticity.** Releases now
   carry `SHA256SUMS.sig` (ed25519, the release key) and `install.sh`
   checks it with OpenSSL 3; versions must look like `v1.2.3`; mirrors must
   be https. The F-Droid tool is pinned.
6. **Low: admin-scoped keys** could start sync rounds and read webhook URLs
   (which often hold the receiver's credentials). Sync rounds are
   people-only; keys see webhook URLs without path or query.
7. **Low: syncing policy and automations together** removed trusted
   automations' own allow rules on the other daemons. Those rules
   (`auto_…`) no longer sync.

Also found while building the People page: creating accounts wasn't limited
to signed-in people, so an owner's admin key could create an admin account
and sign in as it. Account management is people-only now.

Two flaky tests found by CI (an automation trigger and a webhook delivery
record) wait for their condition instead of racing it.

## 2026-11-03 · Phases 17–20 — After v0.1.0

The build had about 39 hours left after v0.1.0, so the work went on with
everything the plan promised that wasn't built yet.

**Phase 17: modules.** Seven modules that the plan had only scaffolded now
work, each with tests against a fake API and a docs page: Kubernetes (REST,
no client library; scale with undo, rolling restart, logs, events),
Proxmox VE (API tokens, certificate fingerprint pinning; start, shutdown,
snapshots with undo), AWS (hand-written SigV4 checked against AWS's test
vectors; EC2, S3, CloudWatch alarms, a least-privilege IAM policy in the
docs), Slack, Jira (Cloud and Data Center; transitions undo when the
workflow allows), Spotify (refresh-token flow) and OBS Studio
(obs-websocket v5 with authentication). 27 built-in modules in all.

**Phase 18: platform.**
- Outbound webhooks: events POSTed to your URLs, signed
  `t=<unix>,v1=<HMAC-SHA256>`, retried after 2, 20 and 120 seconds,
  switched off after 25 failures in a row, with a delivery log, test button
  and settings page (`docs/api/webhooks.md`).
- Vault import of CSV exports from Bitwarden, 1Password, KeePass, LastPass,
  Proton Pass and browsers.
- One-line installers for Linux, macOS and Windows that verify checksums
  (`docs/install.md`), tested against a fake release in CI.
- Website: changelog and an API reference generated from the OpenAPI specs.
- A browser check of the relay after the phase 15 rekey: a phone-sized
  client paired through a hub, reconnected and received live events.

**Phase 19: sign-in.**
- Hub passkeys (WebAuthn): add, list and remove on the account page; sign in
  without an email address. Tested with a software authenticator and in
  Chrome with a virtual one.
- Daemon single sign-on with OIDC (Google, Microsoft Entra, Okta, Keycloak,
  Authentik…): code flow with PKCE, state and nonce tied to the browser,
  verified email required, domain allow-list, optional account creation as
  member or viewer (`docs/api/sso.md`).
- Daemon passkeys are left out: WebAuthn doesn't allow the IP-address origin
  the desktop app uses.

**Phase 20: sync and phones.**
- Sync between daemons (`docs/architecture/sync.md`): the vault, agent rules
  and automations, merged item by item, through the hub or directly with
  peers on the network, encrypted with a group key only the daemons hold.
  Tested with two real daemons through a real hub. Sync was half built
  before: the hub stored blobs nobody wrote.
- Phone notifications without Google services: one tap sets up an ntfy
  channel with a random topic and a private mode, and notifications open the
  app on the right screen through `conduit://open/…` links.
- An F-Droid repository published with each signed release, next to the
  APK; the Android CI job builds one with a throwaway key to keep the script
  working.

**Changed from the plan**
- The container restarted mid-afternoon and the session lost about four
  hours; no work was lost, since everything was on disk.

## 2026-11-03 · Phase 16 — Release v0.1.0

**Landed**

- v0.1.0 is published: https://github.com/Elchi-dev/conduit/releases/tag/v0.1.0
  (tag on a4c357e). 23 assets: daemon and hub binaries for six platforms
  with `SHA256SUMS`, desktop installers (MSI and setup.exe, two DMGs and app
  archives, deb, rpm, AppImage) and the Android APK.
- Release notes in `docs/releases/v0.1.0.md`, used by the workflow.
- Every job of the release workflow passed on the first run.

**Changed from the plan**

- The build environment can't push tags, so the release was started with
  the workflow's manual trigger, which now creates the tag on the commit it
  runs on. Pushing a `v*` tag still works too.
- The signing secrets aren't set yet, so this release is unsigned: the APK
  won't install until it's rebuilt with the keystore, and installs won't
  treat it as an update. Once the secrets are in place, re-run the release
  workflow for v0.1.0 (or release v0.1.1) to get signed assets.

## 2026-11-03 · Phase 15 — Hardening and security review

**Landed**

- Python, TypeScript and Go external-module kits (`sdk/external`), tested
  against the engine, and API clients for both APIs (`sdk/clients`).
- An independent security review by a separate agent that hadn't seen the
  code being written, covering vault, keys, auth, relay, updater, sandbox
  and hub. Every confirmed finding is fixed:
  1. Agents and keys could add or change module instances (whose settings
     hold credentials) and edit automations during an emergency stop. Now
     only people manage instances and delete automations; while stopped,
     only people save automations.
  2. Relay sessions had no daemon contribution, so a hub could replay a
     recorded hello and its requests. The daemon now sends a fresh ephemeral
     key in its Welcome and both sides switch to session keys mixed with it
     (forward secrecy for both long-term keys, no replays). Go and
     TypeScript updated together; new test vectors and a replay test.
  3. A malformed relayed request could panic the daemon. Relayed requests
     are validated (methods, `/api/` paths, no control characters, scheme or
     host) and a handler panic answers 500.
  4. No sign-in limits on the daemon and per-proxy limits on the hub.
     Failed sign-ins are limited per source and per account on both; the hub
     takes client addresses from `X-Forwarded-For` behind a proxy
     (`CONDUIT_HUB_TRUST_PROXY`); Argon2id runs are bounded. The daemon
     checks the Host header against DNS rebinding (`CONDUIT_ALLOWED_HOSTS`).
  5. On closed hubs any invite string passed registration, and the admin
     address was admin before it was confirmed. Invitations are checked
     (address, unused, unexpired); admin rights come with confirmation.
  6. Sandbox modules could follow redirects anywhere and reach CGNAT
     (Tailscale), NAT64 and other reserved ranges. Both are closed.
  7. CSRF protection relied on bodies being non-empty. Cookie-authenticated
     mutations now need a same-origin `Sec-Fetch-Site` or `Origin`.
  8. A leaked key could pull the emergency stop repeatedly. The key that
     pulls it is revoked.
  9. Smaller: webhook and relay limit tables are bounded; one address can't
     take all of a daemon's relay slots; no device tokens in relay URLs;
     TOTP periods are bounded; the updater checks the release channel; MCP
     servers' read-only hints are trusted only when the person says so;
     `servers.read_file` follows the rules for changes and `logs` stays out
     of the audit log.
- A functional bug the review found: approvals for callers that don't wait
  (agents over MCP, automations, the brief) never ran. Approved calls now run
  in the background after a fresh policy check, and the approval records the
  audit entry (`resultSeq`). Approvals left pending across a restart expire.

**Changed from the plan**

- The review found more than expected, so client SDK polish was kept to the
  generated types; the kits and clients are complete but minimal.

## 2026-11-03 · Phase 14 — Website

**Landed**

- `site/`: an Astro static site any hub serves (`CONDUIT_HUB_SITE_DIR`; the
  Docker image builds it in). Landing page with the app's lamp row and an
  approval card as the one animated moment, downloads, a page on hubs, and
  the whole `docs/` folder rendered with links rewritten to site URLs.
- Hub account pages on the same origin as the hub API: sign-in and sign-up,
  email verification, password reset, invitations, pairing codes with a
  countdown, devices with presence, API keys with scopes (secret shown once),
  organisations with members and invitations.
- Verified in a browser against a running hub: verify link, sign-in, pairing
  code, key creation, organisation creation. Phone layout checked at 412 px.
- CI builds the site.

**Changed from the plan**

- The registry browser and API reference pages are left for later; the
  docs pages cover the API and the registry protocol.

## 2026-11-03 · Phase 13 — Modules and remaining features

**Landed**

- Eight new modules, each with docs and tests against fake APIs: GitHub,
  GitLab, Cloudflare (record changes preview as diffs and undo), Home
  Assistant (toggles and light changes undo), Discord (webhook or bot),
  files and backups (folders, restic/rsync/command jobs, overdue and
  free-space warnings), games (local Steam library, launch, running games,
  start/stop events) and notes (Markdown folder; every change undoes).
- Feature 9, ambient status: four states (ok, attention, down, stopped)
  pushed on change to a Home Assistant light, a webhook or Discord, and
  served at `GET /api/v1/ambient` for polling devices; a Stream Deck plugin
  scaffold in `integrations/streamdeck`.
- Feature 11, hub-free pairing: daemons that listen on the network serve the
  relay protocol at `/relay`; pairing codes carry the address; clients try it
  before the hub. Verified in a browser with the hub switched off.
- Feature 12, sandboxed modules: wasip1 modules run in wazero with no files,
  no environment and no sockets; HTTPS only to granted hosts (and never to
  private addresses); `pkg/sdk/wasm` for Go modules; tested with a real
  module built in the test, including host callbacks.
- Feature 7, rotation: `vault.rotate` with a Cloudflare token provider and a
  provider interface.

**Changed from the plan**

- Hub-free pairing and the WebAssembly sandbox were planned as scaffolds;
  both work now. mDNS discovery and peer-to-peer sync remain designs, since
  pairing already carries the address.
- The Android build targets arm64 and x86_64 only, which keeps CI time sane
  and covers current phones.

**Fixed**

- Sandboxed Go modules deadlocked: wasip1 blocks the whole runtime on a
  blocking stdin read. The guest now sets stdin non-blocking and the host
  passes a real OS pipe, which wazero can poll.

## 2026-11-03 · Phase 12 — Android

**Landed**

- The Tauri shell builds for Android with the web app bundled; the phone
  reaches daemons through a hub relay. `gen/android` committed with release
  signing from `keystore.properties`, Conduit launcher icons and a
  `conduit://` deep link.
- Pairing by scanning the daemon's QR code in the app, or by opening the
  link from the camera app.
- Feature 6, phone as a hardware key: approving on the phone asks for a
  fingerprint, face or PIN first.
- Feature 13, voice (first cut): dictation into the assistant where speech
  recognition exists; nothing is sent by voice alone.
- In-app update check against GitHub releases; Android's installer enforces
  the signing key.
- Phone layout: compact top bar (lamps scroll, short Stop button),
  scrolling tabs, tags no longer stretch in narrow rows. Checked at 412 px.
- `android.yml` builds the APK (universal) and uploads it; signed when the
  keystore secrets exist.

**Changed from the plan**

- No Firebase push: it would tie every hub operator to a Google project.
  Background alerts go through the notify module's ntfy channel, which has
  its own phone app; the app notifies while open.
- Cleartext HTTP is allowed in the APK so self-hosted hubs on a LAN work;
  relay content is end-to-end encrypted regardless.

**Fixed**

- The desktop sidecar config no longer leaks into the Android build
  (`externalBin` is desktop-only).

## 2026-11-03 · Phase 11 — Desktop

**Landed**

- The desktop shell starts the bundled daemon (or attaches to one already
  running), shows a splash until it answers, then loads the daemon's web app.
  Single instance; quitting stops the sidecar it started.
- Tray with Open, approvals waiting (jumps to Approvals), Emergency stop and
  Quit; the icon turns amber while something needs you. Closing the window
  hides to the tray.
- Native notifications for approval requests, the notify module's desktop
  channel and available updates, only when the window isn't in front.
- Start at login (hidden in the tray). Settings → App shows the version,
  updates and this option.
- Signed desktop updates through the Tauri updater (minisign key generated;
  the release workflow will publish `latest.json`).
- Daemon self-update (`internal/update`): signed release manifest or a hub
  feed, SHA-256 check, binary swap with the old one kept, restart, and
  automatic rollback after three unconfirmed starts. API, `conduitd update`,
  Settings → Updates, `update.available` event, `tools/release` to sign
  manifests. Desktop-managed and dev builds never replace themselves.
- The web app talks to the shell only through `capabilities/daemon.json`,
  which grants the daemon's origin five commands, events and notifications.
- Verified by running the real app under Xvfb: boot, attach, sign in,
  Settings → App over IPC, update check through the updater plugin.

**Changed from the plan**

- The window no longer bundles the web app on desktop; the daemon serves it.
  The bundled page is a small splash, so the app and daemon can't drift.
- The daemon now retries its listen address for ten seconds, so a restarted
  process can take over from the one it replaces.

**Fixed**

- On Linux desktops without an app-indicator library, creating the tray
  panicked and the app crashed at start. The shell now runs without a tray
  there, and closing the window quits.
- Settings put the app's sections first and folds long session lists.

## 2026-11-03 · Phase 10 — Hub and remote access

**Landed**

- `conduit-hub`: accounts (Argon2id, verification, reset, sign-in notices,
  no address enumeration, rate limits), mail through each operator's own
  provider (console, Resend, SMTP), orgs with email invitations and roles,
  pairing codes and device tokens, hub API keys with scopes, encrypted sync
  blobs with optimistic versions, a module registry with ed25519-signed
  versions, and a signed update feed.
- One schema for SQLite and PostgreSQL; the hub test suite passes on both
  (CI runs a Postgres job). Docker image and compose file in `deploy/hub`.
- WebSocket relay: one daemon socket multiplexes up to 64 client sockets; the
  hub sees only ciphertext.
- Daemon side (`internal/remote`): link to a hub with a pairing code, keep
  the tunnel up with backoff, enroll phones by QR code, run relayed requests
  against the normal API (sessions, scopes and policy still apply), remove
  paired devices. Settings → Remote access shows it all, with a QR code and
  key fingerprint.
- Web app relay mode: pair by link, sign in, use everything through the hub
  from any origin. Verified end to end in headless Chrome (static page →
  hub → daemon).
- `api/openapi/hub.yaml` with a route parity test; docs: protocol/hub.md,
  architecture/hub.md, self-hosting guide.

**Changed from the plan**

- The pairing secret no longer travels in the plaintext hello: the client
  seals it, with its device name, into a proof frame. This closes a hole
  where a malicious hub could read the secret and enroll its own key, and it
  makes the daemon admit a key only after the client proves it holds it.
- Go and TypeScript share pinned test vectors (`pkg/relay/testdata`), checked
  in CI, so the two implementations can't drift.

**Fixed**

- Approvals whose waiter was gone (after a restart) stayed pending forever and
  could still be approved. They now expire on read and can't be decided late.

## 2026-11-03 · Phase 9 — AI layer

**Landed**

- Tool catalog from every connected system plus Conduit tools (overview,
  preview, approval status, what changed, timeline, undo, emergency stop),
  filtered by scopes and annotated with read-only/destructive hints.
- MCP server over streamable HTTP (`/mcp`) and stdio (`conduitd mcp`);
  tested end to end including the approval round-trip.
- Providers: Anthropic and any OpenAI-compatible API (cloud, Ollama, LM
  Studio, custom gateways), keys from the vault, local model detection.
- Built-in assistant as a drawer on every screen and from the command bar,
  streaming its steps, with inline approval cards; conversations per user.
  Verified in a real browser against a fake model.
- MCP bridge: outside MCP servers mounted as modules (stdio or HTTP), risk
  from tool annotations; tested by mounting one Conduit into another.
- Signature features: agent dry-run (2), "What changed?" (4) as tool, API
  and timeline panel, record → automate (3) from the timeline.
- Configuration changes are now audited.

**Fixed**

- Dry-run plans with no changes were sent as `null` and crashed the approval
  card; the engine now always sends a list.

## 2026-11-03 · Phase 8 — metrics, uptime checks, automations, daily brief

**Landed**

- **Metrics**: Prometheus alerts, targets, instant queries and charts over
  time; Grafana dashboard search with links; health follows firing alerts.
- **Websites and APIs**: uptime checks with expected status/content,
  latency, certificate expiry and down/up/expiring events; outgoing requests.
- **Automations**: schedule, event (with field matching), webhook and manual
  triggers; up to 20 steps with templated inputs; run history. Trust model:
  people's automations get scoped allow rules, agents' drafts stay disabled
  until a person enables them. Loop protection. Secret webhook addresses with
  rate limits.
- **Daily brief** (signature feature 10): down/degraded systems, approvals,
  unread mail, today's events, recent failures and expiring keys; one click
  schedules it every weekday morning.
- Line charts with a validated colour palette, legend, crosshair and table
  view; links in tables open in a new tab.
- Automations screen with a step builder that reuses each action's form.

**Changed from plan**

- Grafana panels open in Grafana rather than being embedded (embedding needs
  server-side Grafana settings); documented.

## 2026-11-03 · Phase 7 — mail, calendar and notifications

**Landed**

- **Mail** over IMAP/SMTP with provider presets (Gmail, Outlook, iCloud,
  Fastmail, Yahoo, Proton Bridge, custom): inbox, search, read (HTML
  converted to text, never rendered), folders, read/unread/flag (undoable),
  move (undo moves back using the server's new UID), drafts, send with dry
  run and threading. Optional new-mail events. Tested against an in-memory
  IMAP server.
- **Calendar** over CalDAV (read and write) or private ICS feeds (read):
  today, agenda with recurrence expansion, calendars, create (undo deletes),
  delete within your own calendars.
- **Notifications**: ntfy, Telegram, Discord, Slack, signed webhook and
  desktop channels with minimum priority.
- Approval requests and emergency stops are forwarded to every channel that
  opts in, with a link to the approvals screen (tested end to end).

**Changed from plan**

- OAuth sign-in for Gmail and Outlook is not in v0.1.0; app passwords work
  today, as planned. Google Calendar is read through its private ICS address.

## 2026-11-03 · Phase 6 — this computer, servers and Docker

**Landed**

- **This computer** (automatic): overview, processes, temperatures, launch
  profiles (undo ends the process), end-a-process with dry run, and game
  mode (signature feature 8, first cut): pauses listed processes, publishes
  events, optional automatic start when a listed game runs.
- **Server (SSH)**: status, services, service details, journal logs, files,
  read file, start/stop (undoable), restart (dry run), run command. Host keys
  are pinned; first connect shows the fingerprint to check.
- **Docker**: local socket, Windows pipe, SSH-tunnelled remote socket or TCP;
  containers, Compose stacks, stats, logs (multiplexed stream decoded),
  images, start/stop/pause/resume (undoable), restart and whole-stack actions
  with dry runs.
- Shared SSH client with reconnects, output caps and shell quoting.
- Tests against an in-process SSH server and a fake Docker API.
- Result views: objects render as readouts, percentages as meters, lists of
  objects as tables with readable headers.

**Changed from plan**

- No Docker SDK dependency; the module speaks the Engine API directly over
  the chosen transport.

## 2026-11-03 · Phase 5 — vault, leak watch and onboarding presets

**Landed**

- Vault: Argon2id-derived key wrapping a random data key; every secret
  sealed with XChaCha20-Poly1305 bound to its name; optional OS keychain
  unlock; lock on demand and on emergency stop.
- Vault module with list, generate, save (or generate), import `.env`,
  reveal, one-time codes (TOTP, RFC 6238 test vector verified), delete.
- Sensitive actions: input and output never reach the audit log, approvals
  or events (tested end to end).
- Modules can only resolve `secret://` references from their own settings.
- Leak watch (signature feature 7, scanning): find vault secret values in
  text or in a folder tree, reported by name and line, never by value.
- Vault setup and unlock screen; onboarding presets (Developer, Gaming PC,
  Homelab, Team) filter the module catalog.
- Built-in singleton modules are created on start.

**Changed from plan**

- Automatic rotation of leaked credentials stays a documented scaffold, as
  planned for v0.1.0.

## 2026-11-03 · Phase 4 — web app and design system

**Landed**

- Design system: control-room palette (slate, warm ink, amber only for
  "needs you"), Schibsted Grotesk and IBM Plex Mono bundled locally, light
  and dark themes, focus rings, reduced-motion support, narrow-screen layout.
- Shell with the lamp row (live health of every connected system), left
  rail, command bar (Ctrl/⌘+K: pages and every action on every system) and
  an always-visible emergency stop.
- Screens: setup, sign-in, overview, approvals with dry-run plans, timeline
  with search, undo and chain verification, module catalog and connect form,
  per-system action runner, agent rules (presets, rules with expiry, lifting
  the emergency stop), API keys (create, shown once, rotate, revoke, usage),
  settings.
- Schema-driven forms and result views, so any module (built-in or external)
  gets a usable screen with no frontend code.
- TypeScript client types generated from the OpenAPI spec; live updates over
  the event stream.
- The daemon embeds and serves the UI (`-tags ui`, `make daemon`).
- Screenshot review in headless Chrome; fixed punctuation spacing from
  tabular figures, a class-name clash and link-button underlines.

**Changed from plan**

- `wouter` and plain CSS tokens instead of TanStack Router and
  vanilla-extract (ADR 0004).
- TypeScript 7 lacks the compiler API that the type generator needs, so
  `pnpm gen:api` runs the generator with TypeScript 5 in isolation.

## 2026-11-03 · Phase 3 — daemon API, accounts and API keys

**Landed**

- Local accounts with roles (owner, admin, member, viewer), Argon2id
  passwords, sessions (token for native clients, HttpOnly cookie for
  browsers), session list and sign-out, password change.
- First-start setup guarded by a one-time token in the log and
  `<data>/setup-token`.
- API keys: `live`, `test` and `agent` kinds; scopes; IP allow-lists;
  per-key rate limits; expiry; rotation with a grace period; revocation;
  30-day usage log. Secrets hashed, shown once.
- The full daemon REST API (modules, instances, actions with dry runs,
  audit and undo, approvals, policy, panic, keys) and a server-sent event
  stream. Spec in `api/openapi/daemon.yaml`; a test keeps routes and spec in
  sync.
- Panic button (signature feature 5): one call freezes everything, denies
  pending approvals, revokes agent keys and ends other sessions.
- Hard rules independent of scopes: only people decide approvals, change
  policy, create keys or lift panic.

**Changed from plan**

- Server-sent events instead of WebSockets, and hand-written handlers with a
  spec-parity test instead of generated stubs (ADR 0003).

## 2026-11-03 · Phase 2 — core

**Landed**

- SQLite store (pure Go, WAL) with embedded numbered migrations.
- Event bus with prefix subscriptions and non-blocking delivery.
- Permission engine: ordered, expiring rules over actor, module, instance,
  action and risk; four autonomy presets; panic freeze.
- Approval queue: persistent, blocking or non-blocking, with expiry and the
  dry-run plan attached so people approve an exact diff.
- Audit log: append-only, SHA-256 hash chain, verification that pinpoints
  the edited entry, filtering for the timeline view.
- Undo (signature feature 1, engine side): reversible actions return a token;
  undo replays through the policy and links both entries.
- Dry runs (signature feature 2, engine side) and panic mode (signature
  feature 5, engine side).
- External modules over JSON-RPC 2.0 on stdio, with a Go `sdk.Serve` helper;
  the daemon loads every executable in `<data>/modules`.
- Tests for all of the above, race-detector clean.

**Changed from plan**

- Nothing material. The Python and TypeScript external-module starter kits
  move to phase 15 (docs and SDKs).

## 2026-11-03 · Phase 1 — repo skeleton

**Landed**

- Go module `github.com/elchi-dev/conduit` with `cmd/conduitd` and
  `cmd/conduit-hub`; both serve health and version endpoints.
- Public module contract in `pkg/sdk` (manifest, actions with risk levels,
  resources, events, dry-run plans, undo tokens, health).
- Web UI scaffold (Vite, React, TypeScript) with a dev proxy to the daemon.
- Tauri 2 shell in `apps/desktop` that starts the daemon as a sidecar.
- OpenAPI 3.1 stubs for the daemon and hub APIs.
- CI: Go vet/test/build on Linux, macOS and Windows; web build; desktop
  compile check on all three OSes.
- Docs skeleton: architecture overview, module contract, ADRs 0001–0002,
  protocol, API, modules and self-hosting indexes.

**Changed from plan**

- Router: standard library `net/http.ServeMux` instead of chi (ADR 0002).
- Android CI job moves to phase 12, when the Android project is generated.
- Android signing secrets could not be set from the build environment; the
  keystore is generated and handed to the owner (see CONTEXT.md).
