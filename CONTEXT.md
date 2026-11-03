# Project context

The single page to read before working on Conduit. Rewritten at the end of
every work session.

## What Conduit is

A control plane for everything a person or team runs (mail, secrets, servers,
processes, dashboards, games, anything a module can reach), where AI agents can
act under configurable rules. It must suit a developer, a gamer, a homelab
owner and a company equally; never tailor it to one setup.

## Current state

- **Version target:** v0.1.0, due Thu 2026-11-05 00:00 CET.
- **Phase:** 12 of 16 (Android) — done 2026-11-03 ~03:10 CET.
- **Works today:** core engine; accounts, keys; daemon API and events; web
  app (now with a phone layout); 12 built-in modules; automations and the
  daily brief; MCP server and stdio bridge; AI providers and the assistant
  (with voice dictation where supported); outside MCP servers as modules;
  what-changed and record-to-automation; `conduit-hub` (accounts, orgs,
  pairing, relay, sync, signed registry and update feed; SQLite or Postgres;
  `deploy/hub`); daemon remote access with QR pairing; desktop shell (tray,
  notifications, start at login, signed updates); daemon self-update with
  rollback; Android app (QR scan, deep links, biometric approvals, APK
  update check) built in CI (`android.yml`).
- **Next:** phase 13: ambient status (tray done; webhook/device scaffolds),
  hub-free LAN pairing scaffold, WASM sandbox scaffold, GitHub and Home
  Assistant modules. Then 14 (website), 15 (hardening, security review),
  16 (release).
- **Known gaps:** the hub has no web pages yet (sign-up and pairing codes are
  API-only until the public site in phase 14); the relay doesn't carry the
  event stream (relayed clients poll every 10 s); no release has been
  published, so update checks report nothing yet; the Android APK has only
  been built in CI, not run on a device.
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
