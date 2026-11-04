# Pterodactyl

Game servers on a [Pterodactyl](https://pterodactyl.io) or
[Pelican](https://pelican.dev) panel, through the panel's client API: state
and resource use, power, console commands, backups and files.

**Setup.** In the panel, Account, API Credentials, create a key (it starts
with `ptlc_`; application keys, `ptla_`, don't work here) and store it in the
vault. It acts with your account's rights, so it reaches the servers you own
or are a subuser of. Enter the panel address, such as
`https://panel.example.com`. For a self-signed certificate, enter its
SHA-256 fingerprint.

Servers are named by their 8-character identifier (in the panel's address
and in `servers`) or full UUID; backups by UUID.

| Action | Risk | Notes |
| --- | --- | --- |
| `servers` | read | Every server with node, state, CPU, memory, disk, network and uptime, and its limits. |
| `status` | read | One `server`. |
| `start` | write | Refused when it's already running. Undo stops it. |
| `stop` | destructive | Stops it the way its egg says; players are disconnected. Undo starts it. |
| `restart` | destructive | |
| `kill` | destructive | Ends the process at once, without saving. Undo starts it. |
| `command` | destructive, sensitive | One console line (at most 500 characters, no line breaks). The server must be running. The preview shows the command. Sensitive because commands can carry passwords; the panel's API doesn't return the console's reply. |
| `backups` | read | Name, state, size, lock and date. |
| `create_backup` | write | Optional `name`. The panel refuses it when the server's backup limit is reached. Undo deletes it. |
| `delete_backup` | destructive | Locked backups are refused. The preview shows the backup. |
| `restore_backup` | destructive | Overwrites the server's files; `truncate` deletes every file first. Only finished backups. Can't be undone. |
| `files` | read | One `directory` (default `/`), with type, size, mode and date. |

Every power action, command and backup change has a preview. Starting is
write and its undo is the destructive stop, so the permission engine asks
again before an undo stops a server.

**Security.** The key travels in `Authorization`; redirects to another host
are refused. Server identifiers and backup UUIDs are checked before they go
into a request path, and directories must be absolute paths without `..`.
