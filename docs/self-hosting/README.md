# Self-hosting a hub

A hub lets your devices reach your Conduit daemons from anywhere, keeps
encrypted sync blobs, lists modules and serves updates. Each hub is
independent: its operator owns its accounts, its mail settings and its data.
Accounts are not shared between hubs. Daemons work without any hub.

What the hub can and can't see is described in
[docs/protocol/hub.md](../protocol/hub.md#what-the-hub-sees).

## Run it

### Docker Compose with PostgreSQL (recommended)

```sh
cp deploy/hub/.env.example deploy/hub/.env   # then edit it
docker compose -f deploy/hub/compose.yaml up -d
```

The hub listens on `127.0.0.1:7700`. Put a TLS-terminating reverse proxy in
front of it, pass WebSocket upgrades through, and set
`CONDUIT_HUB_TRUST_PROXY=true` so sign-in limits apply per client. With
Caddy:

```
hub.example.com {
  reverse_proxy 127.0.0.1:7700
}
```

### One binary with SQLite

```sh
go build -o conduit-hub ./cmd/conduit-hub
CONDUIT_HUB_URL=https://hub.example.com CONDUIT_HUB_DB=/var/lib/conduit-hub/hub.db ./conduit-hub
```

SQLite runs in WAL mode and suits small hubs (a household, a team). Use
PostgreSQL for anything larger. The schema is identical; migrations run on
start.

### Kubernetes with Helm

The chart in `deploy/helm/conduit-hub` runs the image
`ghcr.io/elchi-dev/conduit-hub` (amd64 and arm64, published with each
release). Its values map onto the variables below.

```sh
helm install hub deploy/helm/conduit-hub \
  --set hub.url=https://hub.example.com \
  --set hub.adminEmail=you@example.com \
  --set mail.driver=resend --set mail.from='Example hub <hub@example.com>' \
  --set secrets.resendKey=re_… \
  --set ingress.enabled=true --set ingress.className=nginx --set ingress.host=hub.example.com
```

- **Database:** SQLite on a persistent volume by default. For PostgreSQL set
  `database.type=postgres` and `database.url`, or keep the URL in your own
  Secret (`secrets.existingSecret` with the keys `DATABASE_URL`,
  `RESEND_KEY`, `SMTP_PASSWORD`).
- **One replica:** the relay holds each daemon's connection in the hub
  process, so the chart runs one pod and replaces it on upgrade
  (`strategy: Recreate`).
- **Ingress:** the relay keeps WebSockets open for hours; raise the proxy
  timeouts (for ingress-nginx, `proxy-read-timeout` and `proxy-send-timeout`
  of `3600`). `hub.trustProxy` is on, so rate limits see each client's
  address from `X-Forwarded-For`.
- **Hardening:** non-root, read-only root filesystem, no service account
  token, all capabilities dropped.

## Configuration

Every setting is an environment variable (flags `-listen`, `-db` and `-url`
override the first three).

| Variable | Default | Meaning |
| --- | --- | --- |
| `CONDUIT_HUB_LISTEN` | `:7700` | Address to listen on |
| `CONDUIT_HUB_DB` | `hub.db` | `postgres://…` URL, or a SQLite file path |
| `CONDUIT_HUB_URL` | `http://localhost:7700` | Public address, used in emails |
| `CONDUIT_HUB_NAME` | `Conduit hub` | Shown in emails |
| `CONDUIT_HUB_ADMIN_EMAIL` | | The account with this address becomes admin once the address is confirmed (by the verification link, a password reset or an accepted invitation) |
| `CONDUIT_HUB_OPEN_REGISTRATION` | `true` | `false`: only the admin and people with a valid invitation to their address can sign up |
| `CONDUIT_HUB_MAIL` | `console` | `console`, `resend` or `smtp` |
| `CONDUIT_HUB_MAIL_FROM` | | Sender, e.g. `Example hub <hub@example.com>` |
| `CONDUIT_HUB_RESEND_KEY` | | Resend API key (driver `resend`) |
| `CONDUIT_HUB_SMTP_HOST` / `_PORT` / `_USER` / `_PASSWORD` | port 587 | SMTP (driver `smtp`; 465 uses TLS, others STARTTLS) |
| `CONDUIT_HUB_RELEASE_KEY` | | Base64 ed25519 public key for the update feed |
| `CONDUIT_HUB_TRUST_PROXY` | `false` | `true` behind a reverse proxy that sets `X-Forwarded-For`, so rate limits see each client's address instead of the proxy's. Leave it off when the hub faces the internet directly |
| `CONDUIT_HUB_SITE_DIR` | `/site` in the Docker image | Serve the website (landing, docs, account pages) from this folder at `/` |

### Mail

Mail is per hub: you bring your own provider. With the default `console`
driver, verification and reset links are only written to the hub's log, which
is fine for trying it out or for a hub only you use (copy the link from the
log). For real use:

- **Resend:** create an API key at resend.com, verify your sending domain,
  and set `CONDUIT_HUB_MAIL=resend`, `CONDUIT_HUB_RESEND_KEY`,
  `CONDUIT_HUB_MAIL_FROM`.
- **SMTP:** any provider; set `CONDUIT_HUB_MAIL=smtp` and the `SMTP_*`
  variables.

`GET /v1/info` reports whether real mail is configured.

### Passkeys

Passkeys work only on the exact address in `CONDUIT_HUB_URL`, which must be
`https://` (browsers allow `http://localhost` for testing). Its host name
becomes the passkey's relying party, so changing the hub's domain later means
people add their passkeys again; their passwords keep working.

## Link a daemon

1. Sign up on the hub (the admin address first) and confirm your email.
2. On the hub's website, open Account and choose Make a pairing code (or
   `POST /v1/pairing-codes` with your session).
3. In Conduit, open Settings, Remote access, enter the hub address and the
   code, and choose Link to hub.
4. Choose Pair a device and scan the code with your phone.

## Operating a hub

Accounts with admin rights (the address in `CONDUIT_HUB_ADMIN_EMAIL`, once
confirmed) see **Hub admin** on their account page (`/account/admin/`):

- **Overview:** accounts (confirmed, admins, switched off), paired devices
  and daemons, daemons connected to the relay right now, organisations,
  sync blobs and their size, registry packages and releases.
- **Accounts:** search by email or name, see devices and the last sign-in,
  and:
  - **Switch off:** ends the account's sessions, revokes its devices and API
    keys, drops its daemons' relay connections and refuses sign-in. Switching
    it back on allows sign-in again; devices and keys stay revoked, so the
    person pairs again.
  - **Delete:** removes everything the hub keeps for the account (sessions,
    devices, keys, sync blobs, passkeys, its registry author handle and
    organisation memberships, and organisations left without members).
    Published registry packages stay, since others may depend on them.

The affected person is told by email each time, and every action is written
to the hub's log with the admin's address. Admins can't switch off or delete
their own account, so a hub always keeps at least one admin who can sign in.
The same actions are in the API under `/v1/admin` (signed-in admins only, no
API keys).

## Back up and upgrade

- Back up the database (`pg_dump`, or copy the SQLite file while the hub is
  stopped, or use `sqlite3 hub.db ".backup out.db"`).
- Upgrade by replacing the binary or image and restarting. Migrations are
  forward-only and run automatically.
- Losing the hub database means people sign up and link their daemons again;
  nothing on the daemons is lost.
