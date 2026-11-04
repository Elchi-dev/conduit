# The module contract

Every integration is a module. The contract lives in `pkg/sdk/module.go`; module
authors import that package and nothing else.

## Manifest

A module describes itself statically:

- identity: `id`, `name`, `version`, `description`, `category`
- `configSchema`: JSON Schema for one instance's settings. Credential fields are
  `secret://<name>` references, resolved by the vault at call time.
- `actions`: each with input and output schemas and a risk level
- `resources`: kinds of things the module can list and open, with a view hint
- `events`: event types it publishes
- `presets`: onboarding presets that enable it by default

Because everything is schema-described, the UI can render a usable screen
(forms, tables, logs, charts) for any module with no frontend code, and every
action becomes an agent tool automatically.

## Risk levels

| Risk | Meaning | Examples |
| --- | --- | --- |
| `read` | Never changes state | list mail, query metrics |
| `write` | Changes state, usually reversible | create DNS record, send draft |
| `destructive` | May lose data or disrupt service | delete, restart, kill, reveal secret |

Risk is the coarsest input to the permission engine; policies can be as
specific as a single action on a single instance.

## Sensitive actions

Actions marked `sensitive` carry secret material. Conduit never writes their
input or output to the audit log, approvals or events: field names and the
`name` field are kept, every other value becomes `"[redacted]"`.

An undo token never holds secret material either. The log keeps a sensitive
action's undo only when it calls an action of the same module that isn't
sensitive itself (that action's input is logged in the clear whenever it
runs, so it carries no secret): creating a key undone by deleting it, a
secret write undone by restoring a version number, a share removed by its
id. An undo that would replay a value (put the old value back) is dropped,
so such an action must not declare itself `reversible` or promise an undo;
when the old value is lost, the action is `destructive`. The daemon's risk
lint (`internal/daemon/risk_lint_test.go`) checks every sensitive,
reversible built-in action against this.

Revealing a credential is destructive: it can't be taken back. Modules whose
job is holding credentials (Conduit's vault, HashiCorp Vault) return only
names and metadata from read actions, and values from a separate `reveal…`
action marked `destructive` and `sensitive`; the risk lint fails any
`reveal…` action below destructive. Other sensitive reads (a KV value, a
mail, a log) return data that may contain a secret, which is why the log
never keeps it.

## Secrets

Credential fields in a config schema should be marked `"x-secret": true`.
Their value is a vault reference (`secret://name`). A module resolves it with
`Host.Secret`, which only succeeds for references that appear in that
instance's own settings.

## Outbound connections

Modules that talk to a server should make their HTTP clients with
`sdk.HTTPClient(host, timeout)` (or `sdk.Transport(host)`) and raw
connections with `sdk.DialContext(host)`. An instance can be attached to one
of the daemon's [networks](networks.md) (userspace WireGuard), and these
helpers send its connections there; with no network, or a host that doesn't
implement the optional `sdk.NetHost`, they behave like Go's defaults.

## Instances

A module can be configured several times (two mail accounts, three Grafana
servers). Each configuration is an *instance* with its own id.

## Dry runs and undo

- Actions marked `dryRun` accept `Call.DryRun` and return a `Plan` — a list of
  concrete changes the UI renders as a diff. Agents use this to show you what
  they intend before you approve.
- Actions marked `reversible` return an `Undo` with the action and input that
  reverse them. The audit log keeps it, so any entry with an undo token gets an
  Undo button.

## Agent context

A built-in module can also implement `sdk.AgentContext` to offer agents MCP
resources, MCP prompts and a line in the MCP server's instructions. Each
entry names a read action that produces its content, so the permission
engine and audit log apply. See `docs/api/mcp.md`.

## Built-in vs external modules

- **Built-in** modules implement `sdk.Module` and are compiled into the daemon.
- **External** modules run as a child process and speak the same contract as
  JSON-RPC 2.0 over stdio. See `docs/protocol/external-modules.md`.
- **MCP servers** can be mounted as modules through the MCP bridge.
