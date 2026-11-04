# Pi-hole

How much your Pi-hole blocks, pause blocking for a while, and block or allow
domains. For Pi-hole v6 and later.

**Setup.** In the Pi-hole web interface, Settings, Web interface / API,
create an app password (or use the web password) and store it in the vault.
Enter the address, such as `http://pi.hole`.

| Action | Risk | Notes |
| --- | --- | --- |
| `summary` | read | Queries, blocked, percentage, active clients, domains on blocklists, and whether blocking is on |
| `top_blocked` | read | The most blocked domains |
| `disable` | destructive | Pause blocking for some seconds (default 300), or until switched back on (0). Undo turns it back on |
| `enable` | write | Turn blocking back on. Undo pauses it again |
| `domain_add` / `domain_remove` | destructive | Blocking or allowing a domain changes what every client can resolve. An exact domain on the deny (default) or allow list. Each undoes the other |

Health is degraded while blocking is paused.

**Security.** The module signs in with the password and keeps the session
only in memory, signing in again when it expires. Domains are checked before
they go into a request path.
