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
front of it and pass WebSocket upgrades through. With Caddy:

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

## Configuration

Every setting is an environment variable (flags `-listen`, `-db` and `-url`
override the first three).

| Variable | Default | Meaning |
| --- | --- | --- |
| `CONDUIT_HUB_LISTEN` | `:7700` | Address to listen on |
| `CONDUIT_HUB_DB` | `hub.db` | `postgres://…` URL, or a SQLite file path |
| `CONDUIT_HUB_URL` | `http://localhost:7700` | Public address, used in emails |
| `CONDUIT_HUB_NAME` | `Conduit hub` | Shown in emails |
| `CONDUIT_HUB_ADMIN_EMAIL` | | This address becomes admin when it signs up |
| `CONDUIT_HUB_OPEN_REGISTRATION` | `true` | `false`: only the admin and invited people can sign up |
| `CONDUIT_HUB_MAIL` | `console` | `console`, `resend` or `smtp` |
| `CONDUIT_HUB_MAIL_FROM` | | Sender, e.g. `Example hub <hub@example.com>` |
| `CONDUIT_HUB_RESEND_KEY` | | Resend API key (driver `resend`) |
| `CONDUIT_HUB_SMTP_HOST` / `_PORT` / `_USER` / `_PASSWORD` | port 587 | SMTP (driver `smtp`; 465 uses TLS, others STARTTLS) |
| `CONDUIT_HUB_RELEASE_KEY` | | Base64 ed25519 public key for the update feed |
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

## Link a daemon

1. Sign up on the hub (the admin address first) and confirm your email.
2. On the hub's website, open Account and choose Make a pairing code (or
   `POST /v1/pairing-codes` with your session).
3. In Conduit, open Settings, Remote access, enter the hub address and the
   code, and choose Link to hub.
4. Choose Pair a device and scan the code with your phone.

## Back up and upgrade

- Back up the database (`pg_dump`, or copy the SQLite file while the hub is
  stopped, or use `sqlite3 hub.db ".backup out.db"`).
- Upgrade by replacing the binary or image and restarting. Migrations are
  forward-only and run automatically.
- Losing the hub database means people sign up and link their daemons again;
  nothing on the daemons is lost.
