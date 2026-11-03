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

## Charts

Outputs shaped `{"series": [{"name", "points": [[unix, value], …]}]}` render as
a line chart (`LineChart.tsx`): one y-axis, 2 px lines, a legend for two or
more series, crosshair tooltip and a table view. Series colours are the
`--series-1…8` tokens in fixed order, validated against both chart surfaces
(dark `#2b2f34`, light `#ffffff`) for colour-vision separation; slots under
3:1 contrast are covered by the always-present legend and table view. More
than eight series are cut, never given generated colours.

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

## Testing

`web/e2e` holds browser tests that drive the real app against a real daemon
with [Playwright](https://playwright.dev). A global setup starts a fresh
daemon (`bin/conduitd`, built with the app inside) on a free port with an
empty data folder, and the first test goes through the real first run with
the setup code from that folder.

```sh
make daemon                 # from the repository root: builds the app and bin/conduitd
cd web && pnpm test:e2e     # CONDUIT_E2E_BIN=… to test another binary, CONDUIT_E2E_LOG=1 for its log
```

Covered, at 1280 px and at 412 px (phone):

- first run: setup code, owner account, overview
- the command bar (Ctrl+K) finds and opens a page
- Modules lists modules; This computer shows its overview by itself
- the vault: create or unlock it, save a secret through the Vault module,
  the value never shown
- a new API key's secret is shown once
- Agent rules: change the default autonomy, and it sticks
- People: add a member
- Settings shows Remote access, Sync, Webhooks, Appearance and Password
- sign out, a wrong password is refused, sign back in
- the emergency stop, pulled and lifted by the person (it runs last: it
  ends other sessions and locks the vault)

Tests use roles and labels (`getByRole`, `getByLabel`), not CSS classes, so
a control without an accessible name fails them. On top, `a11y.spec.ts` runs
[axe](https://github.com/dequelabs/axe-core) on Overview, Modules, an
instance page, Approvals, Timeline and Settings in the dark and the light
scheme, and fails on serious or critical WCAG 2.1 A/AA problems. Tests run
one at a time against one daemon. CI runs them in the `e2e` job and keeps
the Playwright report when they fail.
