# AdGuard Home

What AdGuard Home blocks, pause protection, and keep your own filtering
rules.

**Setup.** Enter the web interface's address (such as
`http://adguard.local:3000`), the username, and the password as a vault
reference.

| Action | Risk | Notes |
| --- | --- | --- |
| `status` | read | Protection on or off, queries, blocked, percentage, average response time, top blocked domains |
| `query_log` | read | Recent queries, optionally only blocked ones |
| `protection_off` | write | Pause protection for some minutes (default 10), or until switched back on (0). Undo turns it back on |
| `protection_on` | write | Undo pauses it again |
| `rule_add` / `rule_remove` | write / destructive | A custom filtering rule, such as `\|\|ads.example.com^` to block or `@@\|\|example.com^` to allow. Each undoes the other |

Health is degraded while protection is paused and down when DNS isn't
running.

**Security.** AdGuard Home's API uses the web interface account with basic
authentication, so use https or keep it on your own network. Rules are one
line each.
