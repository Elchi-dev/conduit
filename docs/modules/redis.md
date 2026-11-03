# Redis

A Redis or Valkey server: version, memory, clients and hit rate, find keys,
look at a key, delete keys or empty a database.

**Setup.** Address (`host:port`), the password (in the vault) and an ACL
user if you use one, the database number, and TLS if the server speaks it.
An ACL user limited to `+info +dbsize +scan +type +ttl +getrange +lrange
+sscan +zrange +hscan +ping` can do everything except deleting.

| Action | Risk | Notes |
| --- | --- | --- |
| `info` | read | Version, uptime, used and maximum memory, clients, keys, hit rate, evicted keys |
| `keys` | read | Keys matching a pattern, found with `SCAN` (never `KEYS`), at most 1000 |
| `get` | read (sensitive) | Type, time to live, and the start of the value (2000 characters, or 50 items). Values are often tokens or sessions, so they stay out of the audit log |
| `delete` | destructive | `UNLINK` one key; preview first |
| `flushdb` | destructive | Empties this database (`FLUSHDB ASYNC`); the preview says how many keys go |

Nothing can be undone: Redis has no way back for a deleted key.
