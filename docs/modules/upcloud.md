# UpCloud

UpCloud servers through the UpCloud API 1.3: state, zone, plan, cores and
memory, start, stop and restart; storage devices and backups, and the
account's credits.

**Setup.** In the UpCloud control panel, People, create a sub-account for
Conduit, allow it API connections (optionally from Conduit's address only)
and give it access to only the servers and storage it should see. Enter
its user name as it is, and store its password in the vault and enter its
`secret://` reference; a plain password is refused.

| Action | Risk | Notes |
| --- | --- | --- |
| `servers` | read | Name, hostname, state, zone, plan, cores, memory and tags |
| `storages` | read | The account's own storage devices and backups: type, size, tier, state and zone |
| `credits` | read, sensitive | Remaining credits as UpCloud reports them (in cents of the account's currency) and as an amount. Never the user name or limits |
| `start` | write | Starts a stopped `server`. Undo stops it again |
| `stop` | destructive | A soft stop that becomes a hard stop after 60 seconds if the OS doesn't shut down: the server's services go down until it's started, and it's still billed. Undo starts it |
| `restart` | destructive | A soft restart of a started server; if the OS doesn't respond within 60 seconds, it's left running rather than forced |

Power actions have previews and are refused when the server isn't in a
state they apply to. Health reports how many servers exist, how many
aren't started, and is degraded when one is in error.

**Security.** Server ids must be UUIDs and the user name is checked when
the settings are saved. The credentials go as HTTP Basic auth; the client
follows redirects only within the same host and never from https to http,
and times out after 30 seconds.
