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
| `records` | read | A zone's or one name's records; fields that can hold passwords (a forwarder's proxy password) are left out, an APP record shows only which app it is (its configuration can hold API keys), and comments are redacted |
| `blocked` | read | The custom blocked list, searchable |
| `allowed` | read | The allowed list, searchable |
| `block_domain` | destructive | Blocks it and its subdomains for every client. Preview first. Undo unblocks it |
| `unblock_domain` | destructive | Takes it off the blocked list. Preview first. Undo blocks it again |
| `allow_domain` | destructive | Lets it through every block list. Preview says when it overrides a block. Undo drops it |
| `drop_allowed_domain` | destructive | Block lists apply to it again, so it may stop resolving. Preview first. Undo allows it again |
| `flush_cache` | write | Next queries are resolved afresh |
| `disable_blocking` | destructive | For 1 to 1440 minutes (default 5); it comes back by itself. Preview first. Undo turns it back on now |
| `enable_blocking` | write | Sends only `enableBlocking=true`, so no other setting changes |

**Risk.** Every list change is destructive, so agents need approval for
it under every preset except full autonomy: blocking (and dropping an
allowed domain) can take down resolution of whatever an agent names, and
unblocking, allowing and pausing weaken filtering. Some names are refused
even with approval, and are for Technitium's console: a single label (`com`,
`lan`, `arpa`) or a public suffix (`co.uk`, `in-addr.arpa`, `github.io`),
for blocking, allowing or dropping, and for blocking or dropping, any name
inside, or above, one of the server's own zones (checked against its zone
list; if that can't be read, the change is refused). A domain already on
a list is refused rather than added twice, so an undo never removes
something you had before.

Health shows the last hour's queries and is *degraded* while blocking is
off or paused. Settings are read only for the two blocking fields; the rest
(which hold proxy and TSIG credentials) is never decoded or returned.
