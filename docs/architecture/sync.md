# Sync

Keeps chosen data the same across a person's daemons: a laptop, a home
server and a work machine, say. Code: `internal/syncer` (engine and
transports), `internal/daemon/sync.go` (collections, API, peer endpoint).

## What syncs

| Collection | Items | Notes |
| --- | --- | --- |
| `vault` | every secret: kind, description, tags and value | Needs the vault unlocked on both sides; a locked vault skips the round. |
| `policy` | the autonomy preset and every agent rule | Rules that name an agent key only match on the daemon that has that key. The rules each daemon makes for its own trusted automations (`auto_…`) don't sync. |
| `automations` | name, trigger and steps | Off by default. A synced automation arrives switched off and untrusted, so it doesn't run on every daemon at once; a person switches it on where it should run. Steps name module instances by id, so they only work where those instances exist. |

Each daemon chooses its own collections. Module settings, keys, sessions,
the audit log and hub links never sync.

## Group key

One daemon starts a group (Settings, Sync) and shows a join code:
`conduit-sync-` followed by the 256-bit group key. Other daemons join with it.
The key is all it takes to read and change what the group syncs, so it is
shown only to signed-in people, every showing is audited, and it should be
handled like a password. Leaving a group forgets the key and the merge
history; local data stays. To shut a daemon out, start a new group on the
others.

## Merge

Every collection is a map from item id to `{updated, deleted, data}`.

1. **Find local changes.** Compare the current data with the last state the
   group agreed on (`sync_state`). New and changed items get the current
   time; items that disappeared become tombstones with the current time.
   A daemon that just joined stamps its existing data with the zero time
   until it has agreed with the group once, so the group's data wins over a
   newcomer's defaults, while items only the newcomer has still join.
2. **Merge.** Item by item, the later update wins. On a tie, a deletion
   wins, then the larger content hash, so every daemon picks the same winner
   in any order.
3. **Apply** what the local side lost, record the merged document as the
   new agreed state.

Tombstones are kept for good (they are small): forgetting one would let an
old copy of the deleted item (a replayed request, or a stale blob a hub
serves) bring it back. The merge uses wall-clock times, so a
daemon whose clock is far off can win or lose conflicts it shouldn't; keep
clocks synced (NTP), as every OS does by default.

Changes arriving by sync are audited with the actor `sync` (`sync_set`,
`sync_delete`, `sync_save`).

## Transports

A round runs every 5 minutes, 10 seconds after a local change (a vault
module action or a settings change through the API), and on **Sync now**.
Each collection goes over every transport that's set up:

- **Hub.** When the daemon is linked to a hub, each collection is one blob
  (`sync-<group id>-<collection>`) written with the hub's version check: on a
  conflict the daemon merges with the newer blob and writes again. Daemons
  meet there only when linked to the same hub account. A blob is at most
  1 MiB after compression and encryption.
- **Peers (feature 11, no hub).** Addresses of other daemons in the group,
  such as `http://192.168.1.20:7600`. A round POSTs the encrypted document to
  `<peer>/sync/exchange`; the peer merges, applies, and answers with the
  merged document, encrypted. The peer must listen beyond loopback
  (`-listen 0.0.0.0:7600`). **Find computers on this network** in the Sync
  settings fills the peers in from mDNS discovery
  (`GET /api/v1/remote/discover`, see
  [protocol/hub.md](../protocol/hub.md#discovery-mdns)); check the key
  fingerprint it shows against the one the other computer shows.

## Encryption

Documents are JSON, gzip-compressed, then sealed with XChaCha20-Poly1305
under the group key with a random 192-bit nonce and the collection name as
associated data. A hub, a network in between or a daemon outside the group
sees only ciphertext and its size. Each document carries the time it was
sealed. `/sync/exchange` needs no session: a request that doesn't decrypt
under this daemon's group key is refused, so is a document sealed more than
15 minutes away from this daemon's clock (a recorded request replayed later),
and the answer is encrypted for the group. It is limited to 60 requests a
minute per source.

## Trust

Every daemon in a group can change the others' synced data, including
loosening the agent rules (policy) or replacing secrets. Only join daemons
you control, and leave out `policy` on a daemon that should keep its own
rules.
