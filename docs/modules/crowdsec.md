# CrowdSec

Active decisions, alerts and their events from a CrowdSec Local API, and
adding or deleting ban decisions, with guards that keep you from locking
yourself out.

**Setup.** On the CrowdSec host, create a machine for Conduit with
`cscli machines add conduit --auto` (it prints the password) and store the
password in the vault; enter `conduit` as the machine id. A machine login
covers everything. To only read decisions, a bouncer key is enough:
`cscli bouncers add conduit`, stored in the vault as `bouncerKey`. With both,
decisions are read with the bouncer key and everything else with the
machine. Leave the address as `http://127.0.0.1:8080` when CrowdSec runs on
the same host, or enter the Local API's address. For a self-signed
certificate, set `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `decisions` | read | Active decisions with id, type, scope, value, time left, origin and scenario, newest first, and counts by type. `ip` finds the decisions covering one address. Community blocklist decisions only with `includeCommunity`. |
| `alerts` | read | Alerts since `since` (default `24h`): scenario, source address, country, network and AS number, event count, start and stop, the machine that raised it and its decisions. `ip` and `scenario` filter. Event details are left out. |
| `alert` | read, sensitive | One alert with its context and up to 50 events (request paths, user agents, target hosts), each value cut to 500 characters with credentials masked. |
| `ban` | destructive | Bans an address or CIDR range for `duration` (default `4h`, 1 minute to 1 year), with `reason` as the decision's scenario. The preview shows the decision; an address already banned is left as it is. Undo deletes the decision. |
| `delete_decision` | destructive | Removes one decision by id, which unblocks that address or range. The preview names the decision. Undo bans it again for the time it had left. |

**Ban guards.** `ban` refuses, before anything reaches CrowdSec:

- this machine's own addresses and the Local API's address (a range
  covering one of them too);
- the addresses and ranges in `protect`, such as your public address or
  your office network;
- private, loopback, link-local, shared (100.64.0.0/10) and unique local
  ranges, unless `allowPrivate` is on;
- ranges wider than /16 for IPv4 or /48 for IPv6, multicast and unspecified
  addresses, and ranges not written from their first address
  (`1.2.3.4/16`; write `1.2.0.0/16`).

**Security.** The machine password is exchanged for a session token, kept
in memory and renewed when it expires; the bouncer key goes in the
`X-Api-Key` header. The client won't follow a redirect to another host or
from https to http. Addresses are parsed as addresses or ranges and ids as
numbers before a request is made. Alerts can carry attacker payloads and
internal host names, so only `alert` returns event details, and it's kept
out of logs.

**Notes.** Bans are added the way `cscli decisions add` adds them, with
`cscli` as the origin, so bouncers and the console show them as manual
decisions. A bouncer key alone can't read alerts or change decisions.
