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
requests authenticated by the cookie must come from the daemon's own pages
(`Sec-Fetch-Site: same-origin`, or a matching `Origin` on older browsers) and
must be JSON, so another site can't act with your session.

Failed sign-ins are limited to 20 per source address and 10 per account in
15 minutes (429 with `Retry-After`); a successful sign-in clears the
account's count. At most a few Argon2id hashes run at once.

### Host names

The daemon answers only under names it is known by: IP addresses,
`localhost` and `*.localhost`, mDNS `*.local` names, and anything listed in
`CONDUIT_ALLOWED_HOSTS` (comma separated). Other names get 421. This stops
DNS rebinding, where a web page points its own domain at 127.0.0.1 to reach
the daemon as if it were same-origin. Put your reverse proxy's name in
`CONDUIT_ALLOWED_HOSTS` if you serve the daemon under one. `/healthz` and
`/hooks/…` are exempt; webhooks are authenticated by their token and limited
to 10 calls a minute each.

Roles map to scopes: owner and admin get `admin:*:*`; members can act, undo
and decide approvals; viewers can only read. A key's scopes are intersected
with its owner's role. See [API keys](../api/keys.md).

## Rules that never depend on scopes

- Only signed-in people decide approvals, change policy, create keys and lift
  panic mode. A leaked key, even with `admin:*:*`, can't approve its own calls
  or loosen the rules.
- Anyone authenticated can pull the panic switch. A key that pulls it is
  revoked as well, so a leaked key can stop things once but not again after
  a person lifts panic mode.
- Only signed-in people add, change or remove module instances (their
  settings hold credentials) and delete automations; while panic mode is on,
  only people can save automations.

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
