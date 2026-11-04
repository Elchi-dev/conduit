# HashiCorp Vault

A HashiCorp Vault or OpenBao server through its HTTP API: health and seal
status, mounts, KV version 2 secrets (names, metadata, one value at a time,
writing and restoring versions), the configured token's own lookup and lease
counts. The module never seals, unseals or changes policies, auth methods or
mounts. (Conduit's own encrypted store is the separate [vault](vault.md)
module.)

**Setup.** Enter the address, such as `https://vault.example.com:8200`, and
store a token in Conduit's vault. Give the token a policy with only what you
want: `read` and `list` on `secret/metadata/*` and `read` on `secret/data/*`
for reading, `create` and `update` on `secret/data/*` for writing. `mounts`
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
| `read_secret` | read, sensitive | The key names of the current (or a given `version`) of a secret. Values come back only for the keys listed in `reveal` (up to 32), so an agent sees exactly the credential it asked for and no other. |
| `write_secret` | destructive, sensitive | Writes a new version with `data` (key to string value), replacing what the secret held; with `merge`, keys not given are kept. The write is check-and-set on the version just seen, so a write in between is refused. The preview lists keys added, changed, unchanged and removed, never a value. Undo restores the previous version. |
| `restore_version` | destructive | Writes an earlier `version` as the new current one (KV v2 keeps the history). Refused when that version is deleted or destroyed, or, with `expectCurrent`, when the secret has moved on since. The preview shows the key names of both versions. Undo restores the version that was current. |
| `token` | read | The token's display name, policies, type, TTL, expiry, renewability and auth path. Never the token or its accessor. |
| `leases` | read | Total leases (and irrevocable ones) from telemetry, or the count under a `prefix` such as `database/creds/app`, listed recursively (up to 200 listings or 10,000 leases, marked as truncated beyond). |

**Undo and the log.** `write_secret` carries secret values in its input,
so it's a sensitive action: Conduit keeps only field names in the audit
log, approvals and events, and doesn't keep its undo token. The output
names the `previousVersion`, and `restore_version` (which carries no values
and keeps its undo) puts it back.

**Security.** The token goes in `X-Vault-Token` (and the namespace in
`X-Vault-Namespace`); since Go forwards custom headers on redirects, the
client follows redirects only within the same host and never from https to
http. Mounts and secret paths are checked segment by segment (no empty
segments, `.` or `..`, only letters, digits and `_ . @ + = : , ~ -` and
spaces) and escaped, and `sys`, `auth`, `identity` and `cubbyhole` are
never taken as KV mounts. Writes first confirm through
`sys/internal/ui/mounts` that the mount is a KV version 2 engine.
