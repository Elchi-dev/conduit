# Architecture

Conduit is a daemon that hosts modules behind one contract, an optional hub
that connects daemons and devices, and thin clients (web, desktop, Android)
that render what the daemon describes.

## Request path

Every call — from the UI, an API key, an agent over MCP or an automation —
takes the same path:

1. **Auth** — a user session, an API key or a scoped agent token.
2. **Permission engine** — evaluates policy rules for (caller, module, action,
   risk) and returns allow, ask or deny.
3. **Approval queue** — "ask" decisions wait for a human, in the app, as a
   desktop notification or on the paired phone.
4. **Module action** — runs, or returns a plan when called as a dry run.
5. **Audit log** — an append-only, hash-chained entry, with an undo token when
   the action is reversible.
6. **Event bus** — publishes the result; the UI and automations react live.

## Subsystems

| Subsystem | Package | Page |
| --- | --- | --- |
| Module contract | `pkg/sdk` | [modules.md](modules.md) |
| Core (registry, events, policy, audit, storage) | `internal/core` | [core.md](core.md) |
| Daemon HTTP, WebSocket, MCP | `internal/daemon` | [daemon.md](daemon.md) |
| Hub | `internal/hub` | [hub.md](hub.md) |
| Web app | `web/`, `internal/ui` | [web.md](web.md) |
| Desktop and Android shell | `apps/desktop` | [desktop.md](desktop.md) |

Pages are written as each subsystem lands. Non-obvious choices are recorded as
[ADRs](adr/).
