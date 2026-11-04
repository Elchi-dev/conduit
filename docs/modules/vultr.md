# Vultr

Your Vultr instances through the Vultr API v2: status, power state, region
and plan, start, halt and reboot; snapshots (take and delete), per-instance
bandwidth and the account balance.

**Setup.** In the Vultr customer portal, open Account, API, and enable the
API key. If you restrict it under Access Control, allow the address
Conduit connects from. Store the key in the vault and enter its
`secret://` reference; a plain key is refused. The key acts as its user, so
a sub-user with only the permissions you want is best.

| Action | Risk | Notes |
| --- | --- | --- |
| `instances` | read | Status, power state, server status, region, plan, OS, vCPUs, RAM, disk and main addresses |
| `snapshots` | read | Description, status, size and when each was taken |
| `bandwidth` | read | An `instance`'s daily incoming and outgoing bytes over the last `days` (1 to 31, 7 by default) with totals |
| `balance` | read, sensitive | Balance (negative means credit), pending charges and the last payment (USD). Never the account's name, email or permissions |
| `start` | write | Starts a stopped `instance`. Undo halts it again. Refused when it's already running |
| `halt` | destructive | Powers a running instance off: its services go down until it's started, and it's still billed. Undo starts it |
| `reboot` | destructive | Reboots an instance |
| `snapshot` | destructive | Takes a snapshot (optional one-line `description`, up to 120 characters). Vultr bills snapshots by size each month, so creating one is destructive. Undo deletes it |
| `delete_snapshot` | destructive | Deletes a `snapshot` for good. The preview shows its description, size and date |

Every action that changes something has a preview. Health reports how
many instances exist and how many aren't running.

**Security.** Instance and snapshot ids must be UUIDs, and days and
descriptions are checked before anything is sent. The key goes as a Bearer
token; the client follows redirects only within the same host and never
from https to http, and times out after 30 seconds. The key can also
destroy instances through the API; Conduit has no action for that.
