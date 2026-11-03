# Hub protocol

Version 1. The HTTP surface is specified in
[`api/openapi/hub.yaml`](../../api/openapi/hub.yaml) (the source of truth;
a test fails if it drifts from the code). This page explains how the pieces
fit and what each party can and cannot see.

A hub is optional. Daemons work local-only without one. Anyone can run a hub
([self-hosting](../self-hosting/README.md)); the default one is just an
instance. Accounts belong to one hub and are never shared between hubs.

## Parties and tokens

| Party | Token | Prefix | Can |
| --- | --- | --- | --- |
| Person | session | `chs_` | everything on their account; 30 days |
| Daemon or client device | device token | `chd_` | relay, sync, registry reads |
| Developer script | hub API key | `chk_` | only its scopes |

Hub API key scopes: `orgs:read`, `devices:read`, `sync`, `registry:read`,
`registry:publish`, `releases:publish` (admins only). Keys and devices can't
create keys, change orgs, make pairing codes or unpair other devices.

Tokens are stored as SHA-256 hashes. Passwords use Argon2id (the same
parameters as the daemon). Sign-in, registration, password reset and pairing
are rate-limited per client address.

## Accounts

- `POST /v1/accounts` sends a verification link. It answers 202 even when the
  address already has an account (the owner of that address gets a notice
  instead), so addresses can't be probed.
- Password reset links last one hour, work once, and end every session.
- Each sign-in sends a notice email; so does pairing a new device.
- Mail goes through the operator's own provider: `console` (log only),
  `resend` or `smtp` (see self-hosting).
- With `CONDUIT_HUB_OPEN_REGISTRATION=false`, only the admin address and
  invited people can sign up.

## Organisations

Roles: owner, admin, member. Owners and admins invite by email (links last
7 days). An invitation can only be accepted by an account with the invited
address, and accepting it also verifies that address. The last owner can't
leave; admins can remove members but not owners or other admins.

## Pairing a daemon with a hub

1. The person signs in to the hub and makes a pairing code
   (`POST /v1/pairing-codes`): 8 characters, 10 minutes, single use.
2. In the daemon (Settings, Remote access) they enter the hub address and the
   code. The daemon calls `POST /v1/devices/pair` with `kind: "daemon"` and its
   X25519 relay public key, and stores the device token it gets back.
3. The daemon keeps a WebSocket to `GET /v1/relay/daemon` open, reconnecting
   with backoff (1 s doubling to 1 min).

## Pairing a client with a daemon

Clients (phones, a browser elsewhere) never need a hub account.

1. In the daemon, the person chooses Pair a device. The daemon makes a random
   one-time secret (valid 10 minutes, kept in memory only) and shows a QR code
   for `conduit://pair?d=<base64url JSON>` where the JSON is
   `{"v":1,"hub":…,"daemon":<device id>,"key":<daemon X25519 public key>,"secret":…,"name":…}`.
2. The client creates its own X25519 key pair, pins the daemon key from the
   QR code, and connects to `GET /v1/relay/connect/{daemon}`.
3. Its first frame is a plaintext hello carrying an encrypted proof (below)
   that includes the secret. The daemon admits the client key and remembers
   it; later connections need no secret.
4. Both sides show the daemon key's fingerprint (first 16 bytes of its
   SHA-256, base64url) so the person can compare them.

## The relay

The hub pipes frames between one daemon socket and many client sockets.

- **Daemon socket.** Binary message = 4-byte big-endian stream id + one
  frame. Text message = `{"type":"open"|"close","stream":n}`.
- **Client socket.** Binary message = one frame. The hub adds and strips the
  stream id.
- Limits: 4 MiB per frame, 64 clients per daemon, 120 client connections per
  address per 10 minutes. Pings every 30 s.
- The hub doesn't authenticate clients; the daemon does. Unpairing a daemon
  device drops its socket.

### Encryption (pkg/relay, web/src/lib/relay.ts)

Keys are X25519. The client sends `{v, static, ephemeral, salt, proof}`:

```
ikm   = X25519(e_c, S_d) || X25519(s_c, S_d)
c2d   = HKDF-SHA256(ikm, salt, "conduit-relay-v1 c2d")   (32-byte AES key)
d2c   = HKDF-SHA256(ikm, salt, "conduit-relay-v1 d2c")
frame = AES-256-GCM(key, nonce = 0x00000000 || uint64_be(counter), plaintext)
```

Each direction has its own key and counter starting at 0.

- `proof` is the client's frame 0: `{"name":…,"pairingSecret":…}`. If it
  opens, the client holds the private half of `static` and pinned the right
  daemon key, and the secret never crossed the hub in the clear. A failed
  proof closes the stream without an answer.
- The daemon's frame 0 is a welcome: `{"ok":true,"client":<id>,"daemon":<name>}`
  or `{"ok":false,"error":…}`.
- Then each client frame is a request
  `{"id","method","path","headers","body"(base64)}` and each daemon frame a
  response `{"id","status","headers","body"(base64)}`. Requests may overlap;
  responses are matched by id and sealed in the order they finish.
- Replayed, reordered or altered frames fail to open and end the stream.

`pkg/relay/testdata/vectors.json` pins the format; Go and TypeScript tests
both check against it.

### What a relayed request can do

The daemon runs relayed requests against its normal API handler, so they
still need a daemon session or API key, and every action still passes the
permission policy. Only `/api/…` paths are reachable. Headers other than
`Authorization`, `Content-Type`, `Accept` and `Idempotency-Key` are dropped
(no cookies). The event stream isn't carried yet; relayed clients refresh on a
timer instead. A paired client can be removed in Settings, Remote access; it
can't open new sessions afterwards.

### What the hub sees

Account emails and names, device names and kinds, the daemon's public key,
when devices are online, stream ids, frame sizes and timing, and sync blob
sizes. It never sees request or response content, pairing secrets, daemon
sessions, vault contents or sync blob contents.

## Without a hub (local network)

Signature feature 11. When the daemon listens beyond loopback (for example
`-listen 0.0.0.0:7600`), it serves the same relay protocol itself at
`GET /relay`: one WebSocket is one stream, the first binary frame is the
hello, every later frame is encrypted exactly as above. The pairing payload
then carries `"lan":"ws://<address>:<port>/relay"` (private IPv4 addresses
and 100.64.0.0/10, so Tailscale-style overlays work too), and pairing works
with no hub at all. Clients try the LAN address first (2.5 s) and fall back to
the hub. At most 16 direct connections at a time.

LAN discovery (mDNS) and peer-to-peer sync between daemons are designed but
not built: pairing carries the address, so discovery isn't needed to connect.

## Sync

`/v1/sync/{key}` stores opaque blobs the client encrypted itself (at most
1 MiB each, 1000 per account). Writes carry the version last seen (0 to
create); a mismatch answers 409 with the current blob, so clients merge and
retry.

## Registry

Authors register a handle and an ed25519 public key. A version is published
as `{payload, signature}` where `payload` is base64 of the exact JSON bytes of
a `VersionPayload` (`name`, `version`, `description`, `homepage`,
`manifest`, `artifacts: [{platform, url, sha256}]`) and `signature` is
ed25519 over those bytes. The hub verifies before storing, serves the payload
unchanged, and returns the author key with the package, so daemons verify
again and don't have to trust the hub. Names are `handle/module`; versions are
immutable semver and can be yanked. "Latest" skips yanked versions and
prefers releases over pre-releases.

## Update feed

Releases are `{payload, signature}` too, signed with the hub's release key
(`CONDUIT_HUB_RELEASE_KEY`). Only hub admins with a session or a
`releases:publish` key can publish. `GET /v1/updates/{component}/{channel}/{platform}?current=x`
answers the newest release, or 204 when the caller is current. Clients verify
with the release key compiled into them, so a compromised hub can't push an
update. The client side lands in phase 11.
