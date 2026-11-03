# Project context

The single page to read before working on Conduit. Rewritten at the end of
every work session.

## What Conduit is

A control plane for everything a person or team runs (mail, secrets, servers,
processes, dashboards, games, anything a module can reach), where AI agents can
act under configurable rules. It must suit a developer, a gamer, a homelab
owner and a company equally; never tailor it to one setup.

## Current state

- **Released:** v0.1.0 on 2026-11-03 (~03:55 CET).
  https://github.com/Elchi-dev/conduit/releases/tag/v0.1.0
- **Since v0.1.0 (phases 17–20, see BUILD_LOG.md):** 7 more modules (27 in
  all), signed outgoing webhooks, password-manager CSV import, one-line
  installers, changelog and API reference pages, hub passkeys, daemon OIDC
  single sign-on, a People page, sync between daemons (hub or peers), phone
  notifications through ntfy, an F-Droid repository with signed releases.
- **Next:** phase 21: a second independent security review of everything
  since v0.1.0 (running), fixes; phase 22: release v0.2.0, docs, handover.
  The build window ends Thu 2026-11-05 00:00 CET.
- **Releasing:** push a `v*` tag, or run the release workflow by hand with
  a tag name (it creates the tag on the commit it runs on; the build
  environment can't push tags). Notes come from `docs/releases/<tag>.md`.
- **Known gaps:** releases are unsigned until the signing secrets are set
  (the APK won't install, installs don't see updates, no F-Droid repo); the
  APK hasn't been tried on a device; the repository is private, so the
  Android update check (GitHub API) can't see releases until it's public;
  daemon passkeys aren't possible on the desktop app's IP-address origin.
- **Settings added since v0.1.0:** `CONDUIT_ALLOWED_HOSTS` (daemon, extra
  host names), `CONDUIT_HUB_TRUST_PROXY` (hub behind a reverse proxy).
- **Working method:** independent pieces (modules, site pages, installers,
  passkeys, SSO) were built by parallel helper agents in separate folders,
  then reviewed, registered and committed here. Check with `pnpm build` (it
  runs `tsc -b`), not `tsc --noEmit -p .`, which misses errors.
- **Screenshots:** a headless-Chrome script reviews UI changes; keep using it
  (Chrome is at /usr/bin/google-chrome in the build environment).

## Rules for working in this repo

- Go for daemon, hub and APIs (ADR 0001). Pure Go only; `CGO_ENABLED=0` builds.
- OpenAPI specs in `api/openapi` are the source of truth for every HTTP API.
- Every module implements `pkg/sdk.Module`; every action declares a risk level.
- Every call goes through the permission engine and the audit log. No bypasses.
- Conventional commits (`feat:`, `fix:`, `docs:`, `chore:` …). No attribution
  trailers or tool signatures in commits, pull requests or files.
- Document as you go: a page in `docs/` per subsystem and module, an ADR for
  every non-obvious choice, an entry in BUILD_LOG.md per phase.

## Decisions waiting on the owner

- **License.** Not chosen yet; no LICENSE file is committed. Until one is
  added the code is all-rights-reserved by default.
- **Release signing secrets.** Three signing keys were generated outside the
  repo (handed over with the build). Add them as GitHub Actions secrets before
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
