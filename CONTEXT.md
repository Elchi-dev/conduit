# Project context

The single page to read before working on Conduit. Rewritten at the end of
every work session.

## What Conduit is

A control plane for everything a person or team runs (mail, secrets, servers,
processes, dashboards, games, anything a module can reach), where AI agents can
act under configurable rules. It must suit a developer, a gamer, a homelab
owner and a company equally; never tailor it to one setup.

## Current state

- **Released:** v0.1.0 and v0.2.0 (3 Nov), v0.3.0 and v0.3.1 (the first
  signed release), and **v1.0.0 (Wed 4 Nov, 05:49 CET)** with 105 modules
  and signed builds for every platform (39 files).
  https://github.com/Elchi-dev/conduit/releases
- **Ready for v1.1.0 (on main, not released):** 331 built-in modules,
  security reviews 8–47 and two sweeps of every module fixed (see
  BUILD_LOG.md). Notes are in `docs/releases/v1.1.0.md`. Main passes the
  full local check (Go race tests, web and site builds with i18n, 51
  browser tests, upgrades from every release including v1.0.0).
- **To release v1.1.0:** GitHub Actions has started no jobs since 06:43 CET
  on 4 Nov (every job ends with zero steps; the repository is private, so
  almost certainly its Actions minutes). Make the repository public or
  raise the Actions spending limit, then run the release workflow by hand
  with tag `v1.1.0` (it tags the commit it runs on). Notes come from
  `docs/releases/v1.1.0.md`. There is no separate v1.0.1: its fix (nested
  calls run as the caller, review 12) is in 1.1.
- **Until Actions works:** verify locally before pushing: `gofmt -l .`,
  `go vet ./...`, `go test -race ./...`, `pnpm build` and `pnpm test:i18n`
  in web and site, `CI=true make daemon && cd web && pnpm test:e2e`, and
  `scripts/upgrade_test.sh`.
- **Releasing:** push a `v*` tag, or run the release workflow by hand with
  a tag name. The F-Droid step is allowed to fail (its repo_url must end in
  /repo).
- **Known gaps:**
  - Many modules were built against vendors' documented APIs with fake
    servers only; each page's Notes names what wasn't confirmed live.
  - `vault.set` and `vault.import_env` replace existing secrets with no
    undo (core vault code; modules such as `github.set_secret` treat the
    same thing as destructive).
  - Daemon passkeys work only under a host name, not in the desktop app
    (127.0.0.1) or through the relay.
  - The APK hasn't been tried on a device; the Android update check can't
    see releases while the repository is private.
  - Cloudflare `set_record` can still overwrite records other than DNS
    control names; ambient status lists down connections.
- **Settings added since v0.1.0:** `CONDUIT_ALLOWED_HOSTS` (daemon, extra
  host names), `CONDUIT_HUB_TRUST_PROXY` (hub behind a reverse proxy).
- **Working method:** modules are built by parallel helper agents in their
  own folders, then an independent helper reviews each batch, and every
  commit is verified in a clean worktree (`git worktree add /tmp/wt HEAD`,
  apply the staged diff, build and test there) before pushing. The disk
  allowance is small: `go clean -cache` when it fills.
- **Conventions every module follows:** credentials only as `secret://`
  references; `sdk.HTTPClient` with `rest.SameHostOnly`; inputs checked
  before any request; server text redacted before it is shortened;
  previews on risky actions; destructive money and send actions take the
  values their preview showed and refuse if the target changed; critical
  devices (locks, doors, alarms, heating) need a separate destructive
  action; `internal/daemon/risk_lint_test.go` enforces names and undo rules.

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
