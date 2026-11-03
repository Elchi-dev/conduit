# Core

`internal/core` is the engine every call passes through. It has no HTTP code;
the daemon, the MCP server and automations all call into it.

## Parts

| Part | File | What it does |
| --- | --- | --- |
| Store | `store.go`, `migrations/` | One SQLite file in WAL mode, pure-Go driver, numbered migrations applied at start |
| Event bus | `events.go` | In-process pub/sub by type prefix; slow subscribers drop events instead of blocking |
| Policy | `policy.go` | Ordered rules plus a baseline preset; panic freeze |
| Approvals | `approvals.go` | Persistent queue of calls waiting for a human; callers block or get the approval back |
| Audit | `audit.go` | Append-only, hash-chained log with undo links and integrity verification |
| Engine | `engine.go` | Module and instance registry, and `Invoke`, the single path into a module |
| External modules | `external.go` | Out-of-process modules over JSON-RPC |

## Invoke

`Engine.Invoke(ctx, actor, call, opts)`:

1. Resolve the instance, its module and the action spec (which carries the risk).
2. `Policy.Decide` → allow, ask or deny.
3. **Deny** → audited as `denied`, returns `ErrForbidden`.
4. **Ask** (and not a dry run) → if the action supports dry runs, a plan is
   computed first and attached to the approval, so the person approves an
   exact diff. Then the call blocks until the approval is decided or expires,
   or returns `ErrPending` immediately with `NoWait`. A `NoWait` call still
   runs once approved: the engine waits in the background, checks the policy
   again (so a freeze or a new deny rule in the meantime wins), runs it,
   audits it and records the entry on the approval as `resultSeq`. Approvals
   still pending when the daemon starts are expired, since nothing is
   waiting on them any more.
5. The module runs the call.
6. The result is audited (`ok`, `error` or `planned` for dry runs) with any
   undo token, and an `action.<status>` event is published.

Dry runs only need "not denied", because they change nothing.

## Policy

Actors are `user`, `agent`, `key`, `automation` or `system`. Rules match on
subject (`*`, `kind:agent`, `agent:<id>` …), module, instance, action and risk,
each with `*` as a wildcard, and may expire (for "full autonomy for one hour").
First match by position wins.

When no rule matches, humans acting directly are allowed; everyone else gets
the active preset:

| Preset | read | write | destructive |
| --- | --- | --- | --- |
| `read-only` | allow | deny | deny |
| `ask-writes` (default) | allow | ask | ask |
| `ask-destructive` | allow | allow | ask |
| `full-autonomy` | allow | allow | allow |

## Panic mode

`Engine.Panic` sets a freeze flag checked before any rule: every agent, API
key and automation is denied, even for reads, and all pending approvals are
denied. Humans can still act. The daemon layer additionally revokes agent
sessions and keys. Only a human can call `Unpanic`.

## Audit log and undo

Each entry's SHA-256 hash covers its content and the previous entry's hash.
`Audit.Verify` walks the chain and reports the first entry that was edited or
whose predecessor was removed.

Reversible actions return an undo token (action plus input). `Engine.Undo`
replays it as a normal call — through the policy and audited — and links the
two entries (`undoes` on the new entry, which is hashed; `undone_by` on the
old one, which is outside the hash so marking it doesn't break the chain). An
entry can be undone once.

The audit log, filtered by time, module or actor, is the data behind the
timeline view.
