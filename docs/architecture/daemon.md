# Daemon

`conduitd` hosts the engine and serves the API, the event stream and (from
phase 4) the web UI. Code: `internal/daemon`.

## First start

With no accounts, the daemon generates a one-time setup token, logs it and
writes it to `<data dir>/setup-token` (mode 0600). `POST /api/v1/setup` with
that token creates the **owner** account and signs it in. The file is deleted
on the next start once an account exists. The desktop app reads the file
directly, so desktop users never see the token.

The daemon listens on `127.0.0.1:7600` by default. Reaching it from other
devices goes through the hub relay (end-to-end encrypted) or an explicit
`-listen` address behind your own TLS.

## Authentication

| Token | Prefix | Who | Actor kind |
| --- | --- | --- | --- |
| Session | `cds_` | a signed-in person | `user` |
| API key | `cdt_live_`, `cdt_test_` | a program | `key` |
| Agent key | `cdt_agent_` | an AI agent | `agent` |

Browsers get the session as an HttpOnly, SameSite=Strict cookie; native
clients use the `token` from the login response as a bearer token. Mutating
requests from a browser session must be JSON, which blocks cross-site form
posts.

Roles map to scopes: owner and admin get `admin:*:*`; members can act, undo
and decide approvals; viewers can only read. A key's scopes are intersected
with its owner's role. See [API keys](../api/keys.md).

## Rules that never depend on scopes

- Only signed-in people decide approvals, change policy, create keys and lift
  panic mode. A leaked key, even with `admin:*:*`, can't approve its own calls
  or loosen the rules.
- Anyone authenticated can pull the panic switch.

## Panic

`POST /api/v1/panic` freezes every agent, key and automation (even reads),
denies all pending approvals, revokes every agent key and signs out every
session except the caller's. Live and test keys are frozen but not revoked,
so lifting panic mode restores them.

## Events

`GET /api/v1/events?prefix=…` streams the event bus as server-sent events
(ADR 0003). Event types so far:

| Type | When |
| --- | --- |
| `action.ok`, `action.error`, `action.planned`, `action.denied` | after every call |
| `approval.requested`, `approval.decided` | approval queue changes |
| `instance.saved`, `instance.deleted` | configuration changes |
| `panic.on`, `panic.off` | panic mode |
| `<module>.*` | anything a module publishes |
