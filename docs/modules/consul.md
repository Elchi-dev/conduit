# Consul

A HashiCorp Consul cluster through an agent's HTTP API: members, services
and their health checks, the KV store, and deregistering a service
instance.

**Setup.** Enter the address of a Consul agent, such as
`https://consul.example.com:8501`. With ACLs on, create a token whose policy
allows what you want (`node_prefix "" { policy = "read" }`,
`service_prefix "" { policy = "read" }` and `key_prefix "" { policy = "read" }`
for reading; `key_prefix` `write` on the keys you want to change; `service`
`write` to deregister) and store its secret ID in the vault. Set the
datacenter if it isn't the agent's own. For a self-signed certificate, enter
its SHA-256 `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `members` | read | LAN members with address, status (alive, leaving, left, failed), role (server or client), datacenter and version. |
| `services` | read | Catalog services with tags, instance count and checks passing, warning and critical, and an overall status. |
| `service_health` | read | Each instance of a `service` (only healthy ones with `passingOnly`): ID, node, address, port, tags and checks with status and output (anything that looks like a credential, such as `user:password@` in a URL, a token or a long key, redacted, then clipped to 300 characters). |
| `checks` | read | Checks in a `state` (critical by default; any, passing or warning), up to 500, with output redacted and clipped the same way. |
| `kv_list` | read | Keys and folders under a `prefix` (the next level, or everything with `recurse`), up to 1000. Never values. |
| `kv_get` | read, sensitive | One key's value as text (or `base64` when it's binary), flags, indexes and the session holding a lock on it. The value is never logged, but anything allowed to read can read it: keep credentials in a secrets manager (such as the [hashivault](hashivault.md) module, whose values need the destructive `reveal_secret`), not in Consul KV. |
| `kv_create` | write, sensitive | Creates a key that doesn't exist yet with `value` (or base64 with `base64`). It's check-and-set 0, so it never overwrites: an existing key is refused, and so is one created in between. The preview shows the size, never the value. Undo deletes the key again. |
| `kv_put` | destructive, sensitive | Replaces the value of an existing key (a missing key is refused; `kv_create` makes new ones), check-and-set on the index just seen (or the `cas` you give), keeping the key's flags. The old value is gone for good, so there's no undo. The preview shows sizes and whether the key is locked, never values. |
| `kv_delete` | destructive | Deletes one key (never a tree), check-and-set. The value is gone for good: no undo. |
| `deregister_service` | destructive | Removes one instance of a `service` (the `id` and `node` pick it when there are several). If it's on the configured agent's node, the agent deregisters it (with its checks); otherwise it's removed from the catalog, and the preview warns that an agent that still has it adds it back at its next sync. No undo: re-registering needs the service definition. |

**Undo and the log.** KV values can be secrets, so `kv_get`, `kv_create`
and `kv_put` are sensitive: Conduit keeps only field names in the audit log,
approvals and events. Conduit never keeps an undo token that holds a value,
so only `kv_create` is reversible: its undo is `kv_delete` with the key and
index, which carries no value. Replacing or deleting a value can't be undone,
which is why `kv_put` and `kv_delete` are destructive.

**Security.** The ACL token goes in `X-Consul-Token`; since Go forwards
custom headers on redirects, the client follows redirects only within the
same host and never from https to http. KV keys are checked segment by
segment (no empty segments, `.` or `..`, no `?`, `#` or `%`) and escaped;
service names, instance IDs, node names, datacenters and check states are
checked before they reach a request.
