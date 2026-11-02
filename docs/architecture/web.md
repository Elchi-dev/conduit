# Web app

The UI in `web/` is served by the daemon (embedded with the `ui` build tag)
and reused unchanged by the desktop and Android shells.

## Stack

- React and TypeScript, built with Vite.
- `openapi-fetch` with types generated from `api/openapi/daemon.yaml`
  (`pnpm gen:api`); the generated file `src/api/schema.d.ts` is committed.
- TanStack Query for server state; the live event stream invalidates queries,
  so views update without polling (`src/lib/events.ts`).
- `wouter` for routing and `cmdk` for the command bar (ADR 0004).
- Plain CSS with design tokens as custom properties (`src/styles/base.css`).

## Design language

Conduit is a control room, not a chat app.

| Token | Dark | Light | Use |
| --- | --- | --- | --- |
| `--bg` | `#23262a` | `#eef0f2` | page |
| `--panel` | `#2b2f34` | `#ffffff` | raised surfaces |
| `--line` | `#3a3f45` | `#d9dde1` | dividers, borders |
| `--ink` | `#e6e3dc` | `#1e2328` | text |
| `--signal` | `#f2a93b` | `#c97a06` | **only** "needs you": approvals, degraded |
| `--ok` | `#6fbf8e` | `#2f8a57` | healthy |
| `--fault` | `#e5625a` | `#c23a32` | down, destructive, blocked |

- **Type:** Schibsted Grotesk for the interface; IBM Plex Mono only for real
  data (hostnames, IDs, keys, JSON, logs), never for labels. Tabular figures
  are applied only to numbers that line up (the UI face also widens
  punctuation under `tnum`).
- **Signature element:** the lamp row in the top bar. One indicator per
  connected system, lit by live health; a fault blinks slowly. It is the only
  decorative motion in the app.
- **Structure:** rows and dividers instead of card grids; no shadows except
  the command bar; small radii (4–6 px); left-aligned, dense layouts.
- **Copy:** sentence case, plain verbs, buttons say exactly what happens
  ("Approve", "Revoke", "Lift emergency stop"). Empty states say what to do.

## Schema-driven screens

Every module gets a working screen with no frontend code:

- `SchemaForm` renders an action's input schema (or a module's config
  schema) as a form. Extensions: `x-secret` marks a vault reference,
  `x-multiline` asks for a text area.
- `ResultView` shows a list of objects as a table, multi-line text as a log,
  and anything else as formatted JSON.
- `PlanView` shows a dry-run plan as before/after changes; the same component
  renders plans inside approvals.
- Actions are grouped by risk ("Look", "Change", "Careful"), and the first
  input-free read action runs on open so the page shows data immediately.

Modules that need richer views can add a custom panel under `web/modules/`
(introduced with the first module that needs one).

## Screens

| Route | Screen |
| --- | --- |
| `/` | Overview: health summary, things needing attention, approvals, activity |
| `/approvals` | Approval inbox with plans |
| `/timeline` | Audit log with search, undo and chain verification |
| `/modules` | Catalog; connect a module through its config form |
| `/i/:id` | One connected system: actions, settings, recent activity |
| `/policy` | Agent rules: preset, rules with expiry, emergency stop status |
| `/keys` | API keys: create (shown once), rotate, revoke, usage |
| `/settings` | Theme, devices, password, version |
