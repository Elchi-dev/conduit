# Conduit

One control plane for everything you run: mail, secrets, servers, containers,
dashboards, local processes, games and anything else a module can reach. AI
agents can drive all of it, under rules you set.

> **Status:** pre-release, under active development toward v0.1.0.
> See [BUILD_LOG.md](BUILD_LOG.md) for progress and [CONTEXT.md](CONTEXT.md)
> for the current state.

## How it fits together

Conduit works the way git and GitHub do. The protocol is open, a default hub
is provided, and every install chooses:

- **Local only** — the daemon runs on your machine, nothing leaves it.
- **Default hub** — accounts, device pairing, an end-to-end encrypted relay to
  your phone, sync, the module registry and updates.
- **Your own hub** — run `conduit-hub` yourself; accounts and mail settings
  belong to whoever hosts it.

| Part | Path | Language |
| --- | --- | --- |
| Daemon (`conduitd`) | `cmd/conduitd`, `internal/` | Go |
| Hub (`conduit-hub`) | `cmd/conduit-hub`, `internal/hub` | Go |
| API contracts | `api/openapi` | OpenAPI 3.1 |
| Module SDK | `pkg/sdk`, `sdk/` | Go, plus JSON-RPC for any language |
| Built-in modules | `modules/` | Go |
| App UI | `web/` | TypeScript, React |
| Desktop and Android shell | `apps/desktop` | Tauri 2 (Rust) |
| Public website | `site/` | Astro |
| Documentation | `docs/` | Markdown |

## Build from source

Requirements: Go 1.26+, Node 22 with pnpm 10, and for the desktop shell Rust
stable plus the [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/).

```sh
make build      # web UI, bin/conduitd, bin/conduit-hub
make test
./bin/conduitd  # http://127.0.0.1:7600
```

During UI work run `cd web && pnpm dev`; it proxies `/api` to the daemon.

## Documentation

- [Architecture](docs/architecture/README.md) and [decision records](docs/architecture/adr/)
- [Protocol](docs/protocol/README.md)
- [API](docs/api/README.md)
- [Modules](docs/modules/README.md)
- [Self-hosting a hub](docs/self-hosting/README.md)
