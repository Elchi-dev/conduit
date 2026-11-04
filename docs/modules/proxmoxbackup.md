# Proxmox Backup Server

Datastores and their usage, backup groups and snapshots with their verify
state, recent tasks, and starting verify jobs on a Proxmox Backup Server.

**Setup.** In the PBS web interface, open Configuration, Access Control, API
Token and add a token (for example `root@pam!conduit`, or better a token of
a dedicated user); store its secret in the vault. Give the token a role
under Permissions: `DatastoreAudit` on `/datastore` is enough for the read
actions, and verify jobs need the `Datastore.Verify` privilege on the
datastore (the `DatastoreAdmin` role has it). A token never has more rights than its user. The
address is the server's, port 8007: `https://pbs.lan:8007`.

PBS uses a self-signed certificate by default. Copy its fingerprint from
the Dashboard (Show Fingerprint) into `fingerprint`; Conduit then trusts
exactly that certificate. With a certificate from a public authority
(ACME), leave the fingerprint empty.

| Action | Risk | Notes |
| --- | --- | --- |
| `datastores` | read | Total, used and free space and percent used, the estimated date it fills up, mount and maintenance state, backend, comment and any error. |
| `groups` | read | For a `store` (and optional namespace `ns`): type (`vm`, `ct`, `host`), id, number of snapshots, last backup, owner and comment. |
| `snapshots` | read | Newest first, up to `limit` (100): time, size, verify state (`ok`, `failed` or `none`), protected, encrypted, file count, owner and comment. Filter by `ns`, `type` and `id`. |
| `tasks` | read | Newest first, up to `limit` (50): type, target, user, start, end and result. `store`, `running` and `errors` filter. |
| `verify` | write | Reads back and checks every chunk of the chosen snapshots: a `store`'s root namespace or the namespace `ns` (never its child namespaces: verify those by their own `ns`), one group (`type` and `id`, both needed) or one snapshot (plus `time` from snapshots). Snapshots already verified are skipped unless `ignoreVerified` is false; `outdatedAfter` verifies again after that many days. The preview counts the snapshots it checks; when all of them are verified it reports nothing to change. Conduit reads the new task back and reports a job PBS refused straight away. |

**Security.** The token goes in the `Authorization` header, and the client
won't follow a redirect to another host or from https to http. Datastore
names, namespaces (up to PBS's 7 levels) and backup ids are checked against
PBS's own patterns before they reach a request. The encryption key's fingerprint of a snapshot
is never returned (only whether it's encrypted), task logs are never read,
and server messages are redacted and kept to one short line.

## Notes

- Pruning, garbage collection and deleting snapshots or groups aren't
  offered.
- A verify job causes heavy disk reads for a while; it changes nothing.
