# Project context

The single page to read before working on Conduit. Rewritten at the end of
every work session.

## What Conduit is

A control plane for everything a person or team runs (mail, secrets, servers,
processes, dashboards, games, anything a module can reach), where AI agents can
act under configurable rules. It must suit a developer, a gamer, a homelab
owner and a company equally; never tailor it to one setup.

## Current state

- **Released:** v0.1.0 (~03:55 CET) and v0.2.0 (~20:45 CET) on
  2026-11-03. v0.2.0 has no macOS or Windows desktop installers yet (no
  runners; see BUILD_LOG.md phase 22); re-run its failed jobs to add them. https://github.com/Elchi-dev/conduit/releases
- **v0.2.0 (phases 17–21, see BUILD_LOG.md):** 7 more modules (27 in all),
  signed outgoing webhooks, password-manager CSV import, one-line
  installers that check a signed SHA256SUMS, changelog and API reference
  pages, hub passkeys, daemon OIDC single sign-on (accounts follow the
  provider's `sub`; owners and admins link explicitly), a People page, sync
  between daemons (hub or peers), phone notifications through ntfy, an
  F-Droid repository with signed releases, and the fixes from a second
  independent security review.
- **Since v0.2.0 (phases 23–33, unreleased):** 26 more modules (53), the
  app in German, fixes from a third security review,
  encrypted backups, two-factor sign-in, the `conduit` CLI, a hub operator
  console, mDNS discovery, home tiles, guides, browser tests and an
  accessibility pass in CI, installing signed modules from a hub,
  restricted vault folders for teams.
- **Released v1.0.0 (Wed 4 Nov, 05:49 CET):** 105 modules, signed builds
  for every platform (39 files), owner tests it now.
- **Now:** toward v1.1 before Thu 00:00: 274 modules, reviews through 31
  fixed (review 32 and more batches running) (BUILD_LOG.md). More batches and their reviews in progress. A
  v1.0.1 (the brief fix, review 12) and v1.1 both wait for Actions.
- **CI is down** since 06:43 on 4 Nov: GitHub Actions doesn't start jobs
  (probably the private repository's minutes; the owner was told). Verify
  everything locally before pushing (`go test -race ./...`, web and site
  builds and i18n, `make daemon && cd web && pnpm test:e2e`). Releases
  also need Actions.
- **Backlog** (take the next item when a phase ends; the build runs until
  Thu 2026-11-05 00:00 CET):
  1. Daemon passkeys (serve the desktop app on localhost, which WebAuthn
     allows).
  2. Translate the website (after the app).
  3. More modules (in progress: Grafana, GitHub Actions, Portainer,
     Immich, Paperless-ngx); after that: Home Assistant automations,
     Backblaze B2, Synology DSM, Mattermost.
  4. Mobile: home tiles as an Android widget; quick approve from the
     notification.
  5. A fourth review of whatever lands after v0.3.0; v0.4.0 before the end.
- **Upgrades:** `scripts/upgrade_test.sh` (CI job `upgrade`) builds every
  earlier release, sets it up, then starts the current daemon on its data.
- **Releasing:** push a `v*` tag, or run the release workflow by hand with
  a tag name (it creates the tag on the commit it runs on; the build
  environment can't push tags). Notes come from `docs/releases/<tag>.md`.
- **Known gaps:** macOS CI jobs stopped getting runners on the afternoon
  of 3 Nov (queued 15 minutes, then cancelled), probably the private
  repository's Actions minutes; Linux and Windows run. Releases are unsigned until the signing secrets are set
  (the APK won't install, installs don't see updates, no F-Droid repo); the
  APK hasn't been tried on a device; the repository is private, so the
  Android update check (GitHub API) can't see releases until it's public;
  daemon passkeys work only under a host name (a browser at localhost, or
  a name in CONDUIT_ALLOWED_HOSTS), not in the desktop app, which opens
  127.0.0.1 (WebAuthn refuses IP addresses), nor through the relay.
- **Settings added since v0.1.0:** `CONDUIT_ALLOWED_HOSTS` (daemon, extra
  host names), `CONDUIT_HUB_TRUST_PROXY` (hub behind a reverse proxy).
- **Working method:** independent pieces (modules, site pages, installers,
  passkeys, SSO) were built by parallel helper agents in separate folders,
  then reviewed, registered and committed here. Check with `pnpm build` (it
  runs `tsc -b`), not `tsc --noEmit -p .`, which misses errors.
- **Screenshots:** a headless-Chrome script reviews UI changes; keep using it
  (Chrome is at /usr/bin/google-chrome in the build environment).

**License:** MIT for everything (owner's decision, 4 Nov).

## Rules for working in this repo

- **Never ask the owner anything during the build** (owner, 4 Nov 02:33:
  "work 100% on your own"). Take the most reasonable choice, note it in
  BUILD_LOG.md, and keep going. If a helper is stopped, restart the work.
  Target: v1.0.0 with as many modules as possible by Thu 5 Nov 00:00 CET.

- Go for daemon, hub and APIs (ADR 0001). Pure Go only; `CGO_ENABLED=0` builds.
- OpenAPI specs in `api/openapi` are the source of truth for every HTTP API.
- Every module implements `pkg/sdk.Module`; every action declares a risk level.
- Every call goes through the permission engine and the audit log. No bypasses.
- Conventional commits (`feat:`, `fix:`, `docs:`, `chore:` …). No attribution
  trailers or tool signatures in commits, pull requests or files.
- Document as you go: a page in `docs/` per subsystem and module, an ADR for
  every non-obvious choice, an entry in BUILD_LOG.md per phase.

## Decisions waiting on the owner

- **Release signing secrets: done.** The owner stored all seven on 4 Nov
  (~01:10 CET); releases from v0.3.1 on are signed. Notes on each key: Add them as GitHub Actions secrets before
  the first release; keep offline backups, since losing a key means existing
  installs can no longer update:
  - Android: `ANDROID_KEYSTORE_BASE64`, `ANDROID_KEYSTORE_PASSWORD`,
    `ANDROID_KEY_ALIAS`, `ANDROID_KEY_PASSWORD`.
  - Desktop updater (Tauri, minisign): `TAURI_SIGNING_PRIVATE_KEY`,
    `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`. Public key is in tauri.conf.json.
  - Daemon releases (ed25519): `CONDUIT_RELEASE_PRIVATE_KEY`. Public key is
    `internal/update.ReleaseKey`.
- **Default hub hosting and domain.** Deferred until it is worth it.

## Where things are

See the table in README.md. Plan and schedule: the Conduit 48-hour build plan
document kept alongside the project.
