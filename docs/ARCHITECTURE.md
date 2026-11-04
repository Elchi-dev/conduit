# Architecture

<p align="center"><img src="images/ori/working.svg" width="120" alt="Ori typing on a laptop"></p>

Conduit is a daemon that hosts modules behind one contract, an optional hub
that connects daemons and devices, and thin clients that render what the
daemon describes. The rule: **every call, from a person or an agent, passes
the policy engine and lands in the audit log.** There are no bypasses.

```
  web app · desktop (Tauri) · Android · conduit CLI            AI agents
  +-----------------------------------------------+   +-----------------------------+
  | render what the daemon describes              |   | MCP (/mcp or stdio)         |
  | HTTP + server-sent events                     |   | API keys, agent keys        |
  +-----------------------+-----------------------+   +--------------+--------------+
                          |   directly, or through the hub relay     |
                          v                                          v
  +----------------------------------------------------------------------------------+
  | conduitd (the daemon)                                                            |
  |                                                                                  |
  |   auth --> policy engine --> approvals --> module action --> audit log           |
  |            allow/ask/deny    a person       run or dry run    hash chain, undo   |
  |                                                  |                               |
  |   vault (secret://)          event bus <---------+--> UI, automations, webhooks  |
  +--------------------------------------------------+-------------------------------+
                                                     |
             built-in Go modules · external (JSON-RPC) · WebAssembly sandbox · MCP bridge
                                                     |
                                                     v
               servers, containers, clouds, code, mail, home, media, games ...

  +----------------------------------------------------------------------------------+
  | conduit-hub (optional, self-hostable)                                            |
  | accounts, pairing, end-to-end encrypted relay, sync blobs, registry, update feed |
  +----------------------------------------------------------------------------------+
```

## The request path

| Step | What happens |
| --- | --- |
| Auth | a user session, an API key or a scoped agent token |
| Policy engine | rules over caller, module, instance, action and risk answer allow, ask or deny |
| Approvals | "ask" waits for a person, in the app, as a desktop notification or on the paired phone |
| Module action | runs, or returns a plan when called as a dry run |
| Audit log | an append-only, hash-chained entry, with an undo token when the action is reversible |
| Event bus | publishes the result; the UI and automations react live |

## Where the code is

| Folder | What |
| --- | --- |
| `cmd/conduitd`, `cmd/conduit-hub`, `cmd/conduit` | the daemon, the hub and the command-line client |
| `internal/core` | the engine: registry, events, policy, approvals, audit, storage |
| `internal/daemon` | the daemon's HTTP API, event stream and MCP server |
| `internal/hub`, `internal/remote`, `pkg/relay` | the hub and remote access |
| `pkg/sdk` | the module contract; the only package a module imports |
| `modules/` | the built-in modules, one folder each |
| `api/openapi` | the specs, source of truth for every HTTP API |
| `web/` | the app, served by the daemon and reused by the shells |
| `apps/desktop` | the Tauri shell for desktop and Android |
| `site/` | the website any hub serves |
| `sdk/` | kits for external modules and generated API clients |

## Pages

Each subsystem has its own page in [architecture/](architecture/README.md).

| Page | Covers | Code |
| --- | --- | --- |
| [Overview](architecture/README.md) | the request path and the list of subsystems | |
| [The module contract](architecture/modules.md) | manifests, actions, risk levels, resources, events | `pkg/sdk` |
| [Core](architecture/core.md) | invoke, policy, panic mode, audit log and undo | `internal/core` |
| [Daemon](architecture/daemon.md) | HTTP API, events, MCP | `internal/daemon` |
| [Hub and remote access](architecture/hub.md) | the hub, the relay, pairing | `internal/hub`, `internal/remote`, `pkg/relay` |
| [Vault](architecture/vault.md) | keys, who can read a secret, restricted folders | `internal/vault`, `modules/vault` |
| [Automations](architecture/automations.md) | triggers, steps, trust | `internal/automation` |
| [Sync](architecture/sync.md) | keeping data the same across your daemons | `internal/syncer` |
| [AI layer](architecture/ai.md) | tools, MCP, providers, the assistant, the bridge | `internal/ai` |
| [Networks](architecture/networks.md) | WireGuard tunnels for module instances | `internal/wgnet` |
| [Web app](architecture/web.md) | the UI, design tokens, translations | `web/`, `internal/ui` |
| [Desktop and Android shell](architecture/desktop.md) | what the Tauri shell adds | `apps/desktop` |
| [Architecture decision records](architecture/adr/README.md) | the ADR index | |
| [ADR 0001](architecture/adr/0001-go-backend-tauri-shell.md) | Go for daemon, hub and APIs; Tauri as a thin shell | |
| [ADR 0002](architecture/adr/0002-stdlib-http-router.md) | standard library HTTP routing | |
| [ADR 0003](architecture/adr/0003-api-contract-and-sse.md) | hand-written handlers checked against the spec; server-sent events | |
| [ADR 0004](architecture/adr/0004-frontend-libraries.md) | a small routing and styling layer for the web app | |

Related pages elsewhere:

| Page | Covers |
| --- | --- |
| [Outbound webhooks](api/webhooks.md) | signed events to your own services |
| [WebAssembly sandbox](protocol/sandbox.md) | modules you don't fully trust |
| [Updates](protocol/updates.md) | signed releases and self-update |
| [Website](../site/README.md) | the Astro site in `site/` |
| [Decisions](DECISIONS.md) | every choice that shaped Conduit, newest first |
| [Security](../SECURITY.md) | what Conduit protects against, and how |
