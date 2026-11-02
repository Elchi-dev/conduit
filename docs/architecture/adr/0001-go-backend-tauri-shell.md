# ADR 0001: Go for daemon, hub and APIs; Tauri as a thin shell

- Status: accepted
- Date: 2026-11-03

## Context

Conduit needs a long-running daemon that holds secrets and talks to many
systems, a server anyone can self-host, and native desktop and Android apps.

## Decision

- The daemon, the hub and every API are written in Go.
- The desktop and Android apps use Tauri 2. The Rust side is a thin shell that
  owns the window, tray, notifications and updater, and runs the Go daemon as a
  sidecar on desktop. No product logic lives in Rust.
- The UI is TypeScript and React, served by the daemon and reused by the shell.

## Consequences

- One language for all server logic; static binaries cross-compile to every OS
  with `CGO_ENABLED=0`. Dependencies must therefore be pure Go (e.g. a pure-Go
  SQLite driver).
- Go's standard library covers HTTP, crypto and SSH (`x/crypto`) well.
- The Tauri shell must be kept deliberately small; anything it needs to know
  comes from the daemon's API.
