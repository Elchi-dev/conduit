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

Passkeys are a hub feature for now (see the hub protocol). The desktop app
opens the daemon at `http://127.0.0.1:7600`, and WebAuthn doesn't accept IP
addresses as a relying party, so daemon passkeys would need the app to move
to a host name such as `localhost` first; the phone's relay client has no
stable origin of its own either.

### Single sign-on

Teams can sign in with any OpenID Connect provider (Google Workspace,
Microsoft Entra ID, Okta, Keycloak, Authentik, GitLab…), configured in
Settings, Single sign-on, or with `PUT /api/v1/auth/oidc` (`internal/daemon/oidc.go`):

- Authorization code flow with PKCE (S256), `state` and `nonce`. The state
  is kept in memory for 10 minutes, works once, and is also bound to the
  browser that started the sign-in by an HttpOnly cookie, so a sign-in
  someone else started can't be finished in your browser.
- The ID token's signature, issuer, audience, expiry and nonce are checked;
  the address must be present and `email_verified` true.
- Allowed email domains limit who may sign in. With none set, only addresses
  that already have an account here can sign in. Accounts are made on first
  sign-in only when auto-create is on and domains are set, and only as
  members or viewers.
- Disabled accounts are refused. A success starts an ordinary session and
  is audited as `oidc_login`; a failure redirects to `/?signin_error=<code>`
  and the reason goes to the daemon's log, not the browser.
- The client secret must be a `secret://` vault reference, so the vault must
  be unlocked for single sign-on to work. Password sign-in keeps working
  alongside it.
- `/start` and `/callback` take 30 requests a minute per source. The
  callback must arrive under a host name the daemon accepts (see Host names
  below): behind a reverse proxy, put its name in `CONDUIT_ALLOWED_HOSTS` and
  set the daemon's address in the settings.

Setup per provider: [docs/api/sso.md](../api/sso.md). Single sign-on is for
browsers on the daemon's own address; the phone app and relay mode sign in
with a password.

### Host names

The daemon answers only under names it is known by: IP addresses,
`localhost` and `*.localhost`, mDNS `*.local` names, and anything listed in
`CONDUIT_ALLOWED_HOSTS` (comma separated). Other names get 421. This stops
DNS rebinding, where a web page points its own domain at 127.0.0.1 to reach
the daemon as if it were same-origin. Put your reverse proxy's name in
`CONDUIT_ALLOWED_HOSTS` if you serve the daemon under one. `/healthz` and
`/hooks/…` are exempt; webhooks are authenticated by their token and limited
to 10 calls a minute each.

People are managed on the People page (`/api/v1/users`), by signed-in
people only: an API key, even with `admin:*:*`, can't create, change or
switch off accounts, because a key that could create an admin account could
sign in as it. Nobody changes their own role or switches themselves off, the
owner can't be changed, and only the owner manages admins. Switching an
account off ends its sessions, and its keys stop working while it is off.

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
