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

Passkeys (WebAuthn) are available too; see Passkeys below.

### Two-factor sign-in

People can turn on two-factor sign-in with an authenticator app (Settings,
Two-factor sign-in): TOTP (RFC 6238, SHA-1, 6 digits, 30-second steps),
implemented in `internal/totp`.

- **Setup** needs the password, shows a QR code and the key, and takes
  effect only once a code from the app is confirmed. Ten recovery codes are
  shown once; each works once instead of a code.
- **Sign-in:** a correct password answers `{twoFactor: true, challenge}`
  instead of a session; `POST /api/v1/auth/login/2fa` with the challenge and
  a code (or a recovery code) starts the session. A challenge lasts 5
  minutes and takes 5 wrong codes; wrong codes count toward the sign-in
  limits.
- **Replay:** codes are accepted one step either side of now, and a step
  that was used (or any older one) is refused, so a code can't be used twice.
- **At rest:** secrets are encrypted with XChaCha20-Poly1305 under a random
  key in settings (`auth.totp_key`), bound to the account id; recovery codes
  are stored hashed.
- **Turning it off** or making new recovery codes needs the password and a
  code. For a lost phone without recovery codes, an owner or admin resets it
  (`POST /api/v1/users/{id}/2fa/reset`, same rules as setting someone's
  password: not yourself, never the owner, only the owner for admins); that
  also ends the person's sessions.
- Single sign-on leaves the second factor to the identity provider. API
  keys and agents don't sign in, so two-factor sign-in doesn't apply to
  them.

### Passkeys

People can add passkeys (Settings, Passkeys) and sign in with one instead
of their email address and password (`internal/daemon/passkeys.go`, stored
in `user_passkeys` by `internal/auth/passkeys.go`, using
`github.com/go-webauthn/webauthn` like the hub).

- **Relying party:** the RP ID is the host name the request came to,
  without the port, and the only accepted origin is the request's own
  origin (`https` when the daemon serves TLS, or when the browser's `Origin`
  is `https` at the same host, behind a reverse proxy). WebAuthn refuses IP
  addresses, so passkeys are offered only under a host name: `localhost`,
  `*.localhost`, `*.local`, or a name in `CONDUIT_ALLOWED_HOSTS`. At
  `127.0.0.1` (the desktop app) and through remote access (relay) they
  aren't offered; `GET /api/v1/auth/passkeys/available` says so, and the UI
  hides them. A passkey works only at the name it was added at (stored as
  `rpId`), so open the daemon at `http://localhost:<port>` in a browser to
  use one locally. Browsers allow WebAuthn only in a secure context: `https`,
  or `localhost`.
- **Adding** needs a signed-in person (not an API key or an agent) and the
  password again, since a passkey outlives sessions. At most 20 per
  account. Registration asks for a discoverable credential with user
  verification. Rename and remove your own under `/api/v1/me/passkeys`.
- **Sign-in** is usernameless: `POST /api/v1/auth/passkeys/login/begin`,
  then `…/finish` with the browser's answer starts an ordinary session
  (device name ending in "(passkey)"). Switched-off accounts are refused, and
  a signature counter that goes backwards (a possibly copied key) is refused.
- **Second factor:** a passkey counts as both factors, because the
  authenticator must verify the person (PIN or biometrics; user
  verification is required). Accounts with two-factor sign-in on are not
  asked for an authenticator code when they sign in with a passkey.
- **Challenges** are kept in memory for 5 minutes, work once, and are bound
  to the ceremony type (registration or sign-in), the relying party they
  were started for, and, for registration, the account. A restart only means
  a ceremony in progress starts again.
- **Limits:** failed passkey sign-ins count toward the same 20-per-source
  limit as wrong passwords; wrong passwords when adding one count toward the
  account limit.
- **Password resets:** changing your password, or an owner or admin setting
  it, removes all of that person's passkeys, so whoever sets the new
  password takes the account back from anyone who planted one.
- **Audit:** `passkey_added`, `passkey_removed`, `passkeys_removed` (by a
  password change or reset) and `passkey_login`.

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
