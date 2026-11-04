# Contributing

<p align="center"><img src="docs/images/ori/hi.svg" width="120" alt="Ori waving hi"></p>

Issues and pull requests are welcome. For anything bigger than a fix, open an
issue first so we can agree on the shape before you build it. Security
problems go through [SECURITY.md](SECURITY.md), not a public issue.

## Running it from source

You need Go 1.26, Node 22 and pnpm 10. Everything on the Go side is pure Go
and builds with `CGO_ENABLED=0`.

```sh
make daemon                    # builds web/ and bin/conduitd with the app built in
./bin/conduitd                 # the first start logs a one-time setup token
```

For work on the interface, run the daemon and the Vite dev server side by
side; the dev server proxies the API to the daemon:

```sh
make daemon-dev && ./bin/conduitd     # the daemon without the embedded app (fast)
cd web && pnpm install && pnpm dev    # the app with live reload
```

The website is an Astro site in `site/`:

```sh
cd site && pnpm install && pnpm dev
```

| Command | Builds |
| --- | --- |
| `make daemon` | `bin/conduitd`, the daemon, with the web app embedded |
| `make hub` | `bin/conduit-hub`, the hub |
| `make cli` | `bin/conduit`, the command-line client |
| `make desktop` | the Tauri desktop app with the daemon as its sidecar |

In a fresh worktree with linked `node_modules`, use `CI=true make daemon`;
pnpm refuses a non-interactive install otherwise.

## Before a pull request

```sh
gofmt -l . && go vet ./...
go test -race ./...
(cd web && pnpm build && pnpm test:i18n)
(cd site && pnpm build && pnpm test:i18n)
CI=true make daemon && (cd web && pnpm test:e2e)
scripts/upgrade_test.sh
```

| Check | What it covers |
| --- | --- |
| `go test -race ./...` | the engine, the daemon, the hub and every module, against fake servers |
| `pnpm test:i18n` | every string has its German entry with matching placeholders (web and site) |
| `pnpm test:e2e` | Playwright journeys against a freshly built daemon, at desktop and phone widths, with an accessibility scan |
| `scripts/upgrade_test.sh` | a data folder made by every earlier release still works (needs git, go, curl and jq) |

CI runs the same checks, plus real PostgreSQL and MySQL for the database
module, the hub on PostgreSQL, and the Helm chart.

## Writing a module

Every integration is a module. Start with
[docs/architecture/modules.md](docs/architecture/modules.md), which explains
the contract, and the Go package [pkg/sdk](pkg/sdk), which is all a module
imports. The built-in modules in `modules/` are worked examples.

| You want | Read |
| --- | --- |
| A built-in Go module | [docs/architecture/modules.md](docs/architecture/modules.md), `pkg/sdk/module.go` |
| A module in Python, TypeScript or any language | [docs/protocol/external-modules.md](docs/protocol/external-modules.md), [sdk/external](sdk/external) |
| A module others can install safely | [docs/protocol/sandbox.md](docs/protocol/sandbox.md), [docs/protocol/marketplace.md](docs/protocol/marketplace.md) |

Each module gets a page in [docs/modules](docs/modules/README.md): setup,
actions with risk levels, resources, events, recommended policies, and Notes
naming anything not yet confirmed against the live service.

### Conventions every module follows

- Credentials only as `secret://` references.
- HTTP through `sdk.HTTPClient` with `rest.SameHostOnly`.
- Inputs checked before any request.
- Server text redacted before it is shortened.
- Previews on risky actions.
- Destructive money and send actions take the values their preview showed,
  and refuse if the target changed.
- Critical devices (locks, doors, alarms, heating) need a separate
  destructive action.
- `internal/daemon/risk_lint_test.go` enforces names and undo rules.

## How the repository works

- Go for the daemon, the hub and every API ([ADR 0001](docs/architecture/adr/0001-go-backend-tauri-shell.md)).
- The OpenAPI specs in `api/openapi` are the source of truth for every HTTP
  API; a test keeps the routes and the specs in step.
- Every module implements `pkg/sdk.Module`, and every action declares a risk
  level.
- Every call goes through the permission engine and the audit log.
- Conventional commits: `feat:`, `fix:`, `docs:`, `chore:`.
- Document as you go: a page in `docs/` per subsystem and module, an ADR in
  [docs/architecture/adr](docs/architecture/adr/README.md) for every
  non-obvious choice (and a line in [docs/DECISIONS.md](docs/DECISIONS.md)),
  and an entry in [docs/BUILD_LOG.md](docs/BUILD_LOG.md) per phase.

## Releases

Write the notes in `docs/releases/<tag>.md` and add the short version to
[CHANGELOG.md](CHANGELOG.md). Then push a `v*` tag, or run the release
workflow by hand with the tag name; it tags the commit it runs on. The
workflow builds and signs every platform and uses the notes file as the
release text.
