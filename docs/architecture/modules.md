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
| `destructive` | May lose data or disrupt service, or can't be contained | delete, restart, kill, reveal secret, post publicly |

Risk is the coarsest input to the permission engine; policies can be as
specific as a single action on a single instance.

An agent approved only for `write` must not reach people or places beyond
what the owner set up: **publishing publicly** (a Bluesky or Mastodon post or
reply, a Ghost post), **notifying strangers** (mentions, replies in someone
else's thread, a mailing list send) and **changing access** (moving a
document into another collection, sharing, roles) are `destructive`. Sending
to a room, chat or channel the instance's settings allow (Matrix
`allowedRooms`, Telegram's allowed chats, a configured Discord or Slack
channel) stays `write`. Previews of such actions name everyone they reach:
the accounts mentioned, the author replied to, the destination collection.

## Sensitive actions

Actions marked `sensitive` carry secret or private material. Conduit never
writes their input or output to the audit log, approvals or events: field
names and the `name` field are kept, every other value becomes
`"[redacted]"`. Their dry-run plans are redacted the same way (the summary
becomes "Change to `<action>` (details hidden)", each change keeps only its
`op`), except in an approval shown to someone who can decide it, who needs
the diff: see [core](core.md#plans-of-sensitive-actions). So an action whose
preview quotes private content (a message being redacted, a transaction
being deleted) is `sensitive` even when its input is just an id.

The same goes for undo tokens of actions that aren't sensitive themselves:
they're kept in the clear, so they must not carry private content. An edit
whose old content is private undoes through an id (Outline restores the
revision that was current) or, when the service keeps no such id, has no
undo for the content (BookStack's revision history and Vikunja's
descriptions); the old title or tags can still be put back.

An undo token never holds secret material either. The log keeps a sensitive
action's undo only when it calls an action of the same module that isn't
sensitive itself (that action's input is logged in the clear whenever it
runs, so it carries no secret): creating a key undone by deleting it, a
secret write undone by restoring a version number, a share removed by its
id. A token that holds nothing but an identifier (`id`, `name` or `names`
with plain values, or record numbers under `ticket`, `conversation`,
`note` and `article`, positive integers only) is kept even when the action
it calls is sensitive: a recorded Firefly transaction is deleted by its id,
though `delete_transaction`'s preview is private, and a help desk note by
its ticket's number and its own, though `delete_note` quotes the note. An undo that would replay a value
(put the old value back) is dropped,
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
  they intend before you approve. A dry run needs the policy's decision for
  the action to be allow or ask (not deny). Because a preview can quote what
  the module's reads return, a caller the policy denies any read action of
  the module gets the plan redacted (see [core](core.md#invoke)).
- Actions marked `reversible` return an `Undo` with the action and input that
  reverse them. The audit log keeps it, so any entry with an undo token gets an
  Undo button.

## Nested calls

A built-in module that reads or changes other modules for its caller (the
daily brief, the ambient status's `push`) goes through `Engine.Invoke` as
that caller, taken from `core.ActorFrom(ctx)`, never as the system actor
or another actor with more rights: a call must not get a caller more than
its own policy allows. Parts that aren't module calls (the audit log,
approvals, keys) follow the scopes of the person or key behind the caller.
The system actor is for what Conduit does on its own (health checks,
alerts forwarded to notification channels, pushes when the state changes)
with content and destinations the owner set up. A scheduled job a person
set up acts as that person: the brief run by a trusted automation reads as
whoever saved it last.

Routes that serve module data outside `Invoke` check the policy themselves
(game covers need a games read the policy doesn't deny).

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
