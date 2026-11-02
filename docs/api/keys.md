# API keys

API keys let programs and AI agents call Conduit without a person signed in.
Manage them in the app under **Settings → API keys**, or through the API.

## Kinds

| Kind | Prefix | Acts as | Use it for |
| --- | --- | --- | --- |
| `live` | `cdt_live_` | a program (`key:<id>`) | scripts, integrations, CI |
| `test` | `cdt_test_` | a program (`key:<id>`) | development; easy to spot and clean up |
| `agent` | `cdt_agent_` | an AI agent (`agent:<id>`) | MCP clients, custom agents |

The kind matters to the permission policy: calls with an agent key are
judged by the agent rules and preset, and panic mode revokes every agent key.

## Format

```
cdt_live_5kq2m8x4c1v7_9w3h6t2r8m1n5c4x7v0b2k9q3z6y8a1d
└─┬┘└─┬┘ └────┬─────┘ └──────────────┬────────────────┘
prefix kind   key id       secret (160 bits, shown once)
```

Only a SHA-256 hash of the secret is stored. The `prefix` (everything up to
the key id) is safe to show and log. Keys are rejected if the kind in the
string doesn't match the stored kind.

## Lifecycle

1. **Create** — `POST /api/v1/keys` with a name, kind, scopes, and optionally
   an IP allow-list, a per-minute rate limit (default 120) and an expiry. The
   response contains `secret` exactly once.
2. **Use** — send `Authorization: Bearer <key>`. Every request is logged for
   30 days (`GET /api/v1/keys/{id}/usage`).
3. **Rotate** — `POST /api/v1/keys/{id}/rotate` issues a new key with the same
   settings. The old key keeps working for the grace period (default 24 hours)
   so you can redeploy, then stops.
4. **Revoke** — `DELETE /api/v1/keys/{id}` stops it immediately.

Only signed-in people can create or rotate keys; a key can never mint keys.

## Scopes

Scopes have the form `area:target:access`. `*` is a wildcard.

| Scope | Grants |
| --- | --- |
| `actions:*:invoke` | call any module action (the policy still decides each call) |
| `actions:<module>:invoke` | call one module's actions, e.g. `actions:mail:invoke` |
| `modules:*:read` | list modules, instances and health |
| `instances:*:manage` | create, change and delete module instances |
| `audit:*:read` | read the audit log and timeline |
| `audit:*:undo` | undo audited actions |
| `approvals:*:read` | see approvals and poll their status |
| `approvals:*:decide` | not usable by keys: only signed-in people decide approvals |
| `events:*:read` | subscribe to the live event stream |
| `policy:*:read` / `policy:*:manage` | read / change policy (changing requires a person) |
| `keys:*:manage` | list and revoke keys (creating requires a person) |
| `admin:*:*` | everything above |

A key never has more access than its owner's role. Agent keys cannot be
created with scopes that would let them decide approvals, manage policy or
manage keys.

## Waiting for approval

When the policy says *ask*, an action call returns `202` with an `approval`.
Poll `GET /api/v1/approvals/{id}`, or watch `approval.decided` on the event
stream, then call the action again once it is approved. A dry-run plan is
attached to the approval so the person sees exactly what will change.

## Limits and errors

| Status | Meaning |
| --- | --- |
| `401` | missing, unknown, revoked, expired key, or IP not allowed |
| `403` | scope missing or the policy denied the call (body says which) |
| `429` | rate limit exceeded; retry after the `Retry-After` seconds |
