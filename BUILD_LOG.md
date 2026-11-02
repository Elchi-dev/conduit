# Build log

Newest first. One entry per phase: what landed, what changed from the plan,
and why.

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
