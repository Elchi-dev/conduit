# Hub and remote access

Two packages make a daemon reachable from elsewhere:

- `internal/hub` is `conduit-hub`, the server anyone can run.
- `internal/remote` is the daemon's side: the hub link, the relay tunnel and
  the paired-device list.

`pkg/relay` holds the end-to-end encryption and a Go relay client;
`web/src/lib/relay.ts` and `web/src/lib/connection.ts` are the browser and
Android side. The wire protocol is in [docs/protocol/hub.md](../protocol/hub.md).

## internal/hub

| File | What |
| --- | --- |
| `hub.go` | Config from `CONDUIT_HUB_*`, routes, CORS, rate limiting, helpers |
| `store.go` | One `DB` type for SQLite and PostgreSQL; queries use `?` and are rewritten to `$n` for Postgres |
| `migrations/` | Portable schema (TEXT, INTEGER, BIGINT only; times as RFC 3339 text) |
| `mail.go` | `Mailer` with console, Resend and SMTP drivers, chosen per operator |
| `accounts.go` | Tokens (session, device, key), register, verify, sign in, reset |
| `resources.go` | Orgs and invites, pairing codes and devices, hub API keys, sync |
| `relay.go` | WebSocket relay: one daemon socket multiplexes many client sockets |
| `registry.go` | Signed module registry and the signed update feed |

Tests (`hub_test.go`) run each flow over HTTP against SQLite, and in CI
against PostgreSQL too (`CONDUIT_HUB_TEST_POSTGRES`). `TestRoutesMatchOpenAPI`
keeps `api/openapi/hub.yaml` and the routes in step.

Choices:

- **Everything security-relevant is verified by the client, not the hub.**
  Daemon keys come from QR codes, registry packages and releases carry
  ed25519 signatures the daemon checks itself. A compromised hub can deny
  service and see metadata, nothing more.
- **Anti-enumeration.** Registration and password reset answer the same
  whether or not an address exists.
- **One schema, two databases.** SQLite keeps a one-binary hub possible;
  Postgres is there for larger hubs. No ORM; the `rebind` shim is the only
  dialect code.

## internal/remote

`Service` owns:

- the daemon's X25519 relay key (`settings` table, `remote.relay_key`),
  created on first start;
- the hub link (`remote_link`, one row: hub, device id, device token,
  account);
- enrolled clients (`relay_clients`, by public key, revocable);
- pairing secrets (memory only, 10 minutes, single use);
- the tunnel loop: dial `/v1/relay/daemon`, reconnect with backoff, handshake
  each new stream, then decrypt requests in order, run them concurrently
  against the daemon's `http.Handler`, and seal responses.

Relayed requests reach the same handler as local ones (`App.Server.Handler()`),
with `RemoteAddr` set to `relay` and an `X-Conduit-Relay-Client` header.
Only `/api/` paths and a short header allow-list pass; cookies are dropped,
so relayed clients use bearer session tokens. The SSE event stream answers
501 over the relay for now.

The daemon API for it is `/api/v1/remote` (status), `/remote/link` (link,
unlink), `/remote/pairings` (QR payload) and `/remote/clients/{id}` (remove).
All need `admin:*:*` and a signed-in person; every change is audited.

Threat notes:

- The relay key and hub device token sit in the daemon database, like the
  rest of its local state; anyone with the data folder can impersonate the
  daemon to the hub. They still can't decrypt past sessions without the
  clients' ephemeral keys, and the daemon session or API key is still needed
  to do anything through the API.
- A leaked pairing secret lets one device enroll within 10 minutes. Both sides
  show the key fingerprint, and the new device appears in the list at once.

## Web side

`connection.ts` keeps a profile in localStorage: direct (default, the page was
served by a daemon) or relay (hub, daemon id, pinned key, this device's
private key, daemon session token). `apiFetch` is the `fetch` behind the
generated API client; in relay mode it tunnels requests and stores the token
from sign-in. When no daemon answers the page, the app offers the Connect
screen; Login can also switch to another computer.
