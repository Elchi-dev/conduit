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
- **Phase:** 13 of 16 (modules and remaining features) — done 2026-11-03
  ~02:30 CET.
- **Works today:** everything through phase 12, plus 8 more modules (GitHub,
  GitLab, Cloudflare, Home Assistant, Discord, files and backups, games,
  notes; 20 in total), ambient status (lights, webhooks, Discord, Stream
  Deck scaffold, `/api/v1/ambient`), hub-free LAN pairing at `/relay`,
  WebAssembly sandbox for untrusted modules (`internal/sandbox`,
  `pkg/sdk/wasm`), Cloudflare token rotation in the vault. All 13 signature
  features are at or past their v0.1.0 target.
- **Next:** phase 14, the public website (Astro in `site/`, served by a hub
  with `CONDUIT_HUB_SITE_DIR`, including hub account pages for sign-up,
  verification, reset and pairing codes). Then 15 (hardening, independent
  security review, starter kits, client SDKs) and 16 (release).
- **Known gaps:** hub web pages (phase 14); the relay doesn't carry the event
  stream (relayed clients poll every 10 s); no release published yet; the
  APK has only been built in CI; the repository is private, so the Android
  update check (GitHub API) can't see releases until it's public.
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
