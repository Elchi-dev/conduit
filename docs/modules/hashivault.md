# HashiCorp Vault

A HashiCorp Vault or OpenBao server through its HTTP API: health and seal
status, mounts, KV version 2 secrets (names, metadata, revealing the values
of named keys, writing and restoring versions), the configured token's own
lookup and lease counts. The module never seals, unseals or changes policies, auth methods or
mounts. (Conduit's own encrypted store is the separate [vault](vault.md)
module.)

**Setup.** Enter the address, such as `https://vault.example.com:8200`, and
store a token in Conduit's vault. Give the token a policy with only what you
want: `read` and `list` on `secret/metadata/*` and `read` on `secret/data/*`
for reading, `create` and `update` on `secret/data/*` for writing. (`read` on
`secret/data/*` is what lets `reveal_secret` work; Conduit's policy is what
keeps agents from it without approval.) `mounts`
uses `sys/mounts` when allowed and otherwise lists the mounts the token can
use; counting every lease needs `read` on `sys/metrics`, counting under a
prefix needs `list` on `sys/leases/lookup/<prefix>`. Set the `namespace` on
Vault Enterprise or OpenBao, and `kvMount` if your KV v2 engine isn't at
`secret`. For a self-signed certificate, enter its SHA-256 `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `status` | read | Initialized, sealed, standby, version, cluster name and the seal's type, threshold, shares and unseal progress. |
| `mounts` | read | Secret engines with path, type, KV version and description. |
| `list_keys` | read | Secret names and sub-folders under a `path` (the top when empty). Never values. |
| `metadata` | read | Current and oldest version, every version with created, deleted and destroyed, max versions, check-and-set requirement and custom metadata. Never values. |
| `read_secret` | read | The key names, version and created time of the current (or a given `version`) of a secret. Never values; the old `reveal` field is refused with a pointer to `reveal_secret`. |
| `reveal_secret` | destructive, sensitive | The values of the `keys` named (1 to 32) of the current (or a given `version`) of a secret, and no others, with the ones that aren't there listed as `missing`. Revealing a credential can't be taken back, so it's destructive, like Conduit's own `vault.reveal`: an agent approved for reads and writes can't see a value without approval. |
| `write_secret` | destructive, sensitive | Writes a new version with `data` (key to string value), replacing what the secret held; with `merge`, keys not given are kept. The write is check-and-set on the version just seen, so a write in between is refused. The preview lists keys added, changed, unchanged and removed, never a value. Undo restores the previous version. |
| `restore_version` | destructive | Writes an earlier `version` as the new current one (KV v2 keeps the history). Refused when that version is deleted or destroyed, or, with `expectCurrent`, when the secret has moved on since. The preview shows the key names of both versions. Undo restores the version that was current. |
| `token` | read | The token's display name, policies, type, TTL, expiry, renewability and auth path. Never the token or its accessor. |
| `leases` | read | Total leases (and irrevocable ones) from telemetry, or the count under a `prefix` such as `database/creds/app`, listed recursively (up to 200 listings or 10,000 leases, marked as truncated beyond). |

**Undo and the log.** `write_secret` and `reveal_secret` carry secret
values, so they're sensitive actions: Conduit keeps only field names in the
audit log, approvals and events. `write_secret`'s undo is a
`restore_version` call with the mount, path and version numbers, never a
value, so the log keeps it and the entry gets an Undo button (it's refused
if the secret has moved on since).

**Security.** The token goes in `X-Vault-Token` (and the namespace in
`X-Vault-Namespace`); since Go forwards custom headers on redirects, the
client follows redirects only within the same host and never from https to
http. Mounts and secret paths are checked segment by segment (no empty
segments, `.` or `..`, only letters, digits and `_ . @ + = : , ~ -` and
spaces) and escaped, and a mount with `sys`, `auth`, `identity` or
`cubbyhole` as any of its segments (so also behind a namespace prefix, like
`ns1/sys`) is never taken as a KV mount. Writes first confirm through
`sys/internal/ui/mounts` that the mount is a KV version 2 engine.
