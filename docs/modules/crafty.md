# Crafty Controller

Minecraft servers on [Crafty Controller](https://craftycontrol.com) 4, through
its v2 API: who's online, CPU and memory, power, backups, console commands
and logs.

**Setup.** In Crafty, Panel config, Users, edit a user, API keys: create a key
with the permissions Conduit should have (Commands, Backup, Logs…) and store
it in the vault. Enter Crafty's address, such as
`https://crafty.example.com:8443`. Crafty makes a self-signed certificate on
install: enter its SHA-256 fingerprint (or put Crafty behind a proxy with a
real certificate).

Servers are named by their id: a number on Crafty 4.0 to 4.3, a UUID on 4.4
and later (both shown by `servers`).

| Action | Risk | Notes |
| --- | --- | --- |
| `servers` | read | Every server with state, players, CPU, memory and version. |
| `stats` | read | One `server`: players online and who, CPU, memory, world size, version, message of the day. |
| `start` | write | Refused when it's already running. Undo stops it. |
| `stop` | destructive | Saves and stops; the preview says how many players are disconnected. Undo starts it. |
| `restart` | destructive | |
| `kill` | destructive | Ends the process without saving. Undo starts it. |
| `backup` | destructive | Runs a backup with the server's backup settings, or `backupConfig` (a UUID, Crafty 4.4 and later). Crafty deletes the oldest backups beyond the configuration's maximum, and a configuration can shut the server down while it runs, so the preview reads the configuration and says the maximum, how many backups there are now (so how many go), and whether it shuts the server down (and how many players that disconnects). |
| `command` | destructive, sensitive | One console line, sent to the server's stdin. The server must be running. Sensitive because commands can carry passwords. |
| `logs` | read, sensitive | The last `lines` (default 100, at most 500) of the log. Logs hold IP addresses and anything typed into the console. |

**Security.** The token travels in `Authorization`; redirects to another host
are refused. Server ids and backup configuration ids are checked before they
go into a request path.
