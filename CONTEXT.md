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
- **Phase:** 3 of 16 (daemon API) — done 2026-11-03.
- **Works today:** core engine (policy, approvals, audit chain, undo, dry
  runs, panic, external modules); accounts, sessions and API keys; the full
  daemon REST API and SSE event stream (`api/openapi/daemon.yaml`). No
  built-in modules yet. Placeholder web UI; Tauri shell compiles; CI on three
  OSes.
- **Next:** phase 4, frontend shell — design system, layout, command bar,
  schema-driven module views, approvals inbox, timeline, key management.

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
- **Android signing secrets.** A release keystore was generated outside the
  repo. Add these GitHub Actions secrets before the first signed APK build:
  `ANDROID_KEYSTORE_BASE64`, `ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS`,
  `ANDROID_KEY_PASSWORD`. Keep an offline backup: losing the keystore means
  existing installs can no longer update.
- **Default hub hosting and domain.** Deferred until it is worth it.

## Where things are

See the table in README.md. Plan and schedule: the Conduit 48-hour build plan
document kept alongside the project.
