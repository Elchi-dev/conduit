# Build log

Newest first. One entry per phase: what landed, what changed from the plan,
and why.

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
