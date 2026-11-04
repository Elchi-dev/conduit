# Technitium DNS

A Technitium DNS Server: dashboard statistics, zones and records, the
custom blocked and allowed lists, flushing the cache and pausing blocking.

**Setup.** In the web console, Administration, Sessions, Create Token; give
it to a user allowed to view the dashboard and zones and to change the
blocked and allowed lists (and settings, for pausing blocking). Store the
token in the vault and enter the console's address (`http://dns.lan:5380`)
with its reference. The token is sent in the body of POST requests, never
in a URL.

| Action | Risk | Notes |
| --- | --- | --- |
| `stats` | read | Queries, blocked, cached, NXDOMAIN, failures, clients and the top 10s, for the last hour to the last year |
| `zones` | read | Name, type, DNSSEC, serial, disabled, sync failures (internal zones left out) |
| `records` | read | A zone's or one name's records; fields that can hold passwords (a forwarder's proxy password) are left out |
| `blocked` | read | The custom blocked list, searchable |
| `allowed` | read | The allowed list, searchable |
| `block_domain` | write | Blocks it and its subdomains. Undo unblocks it |
| `unblock_domain` | destructive | Takes it off the blocked list. Undo blocks it again |
| `allow_domain` | destructive | Lets it through every block list. Preview says when it overrides a block. Undo drops it |
| `drop_allowed_domain` | write | Block lists apply to it again. Undo allows it again |
| `flush_cache` | write | Next queries are resolved afresh |
| `disable_blocking` | destructive | For 1 to 1440 minutes (default 5); it comes back by itself. Preview first. Undo turns it back on now |
| `enable_blocking` | write | Sends only `enableBlocking=true`, so no other setting changes |

**Risk.** Blocking more is write; anything that weakens filtering
(unblocking, allowing, pausing) is destructive, so agents need approval for
it under every preset except full autonomy. A domain already on a list is
refused rather than added twice, so an undo never removes something you
had before.

Health shows the last hour's queries and is *degraded* while blocking is
off or paused. Settings are read only for the two blocking fields; the rest
(which hold proxy and TSIG credentials) is never decoded or returned.
