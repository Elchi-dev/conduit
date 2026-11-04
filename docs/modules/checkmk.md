# Checkmk

Hosts and services with their states, current problems and downtimes,
acknowledging problems, and scheduling or ending downtimes, through the
Checkmk REST API with an automation user. Works with Checkmk 2.2 and later,
in every edition.

**Setup.** In Checkmk, open Setup, Users, create an automation user (or use
the built-in `automation`), and store its automation secret in the vault.
Enter the site's address, such as `https://monitor.example.com/mysite`, and
the user's name. The user needs a role that sees the hosts; acknowledging
and downtimes need the matching permissions (a normal monitoring user has
them). For a self-signed certificate, set `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `hosts` | read | Name, address, state (UP, DOWN, UNREACHABLE, PENDING), output, since when, acknowledged, in downtime, and how many services are WARN, CRIT or UNKNOWN. `problemsOnly` filters. At most 1000. |
| `services` | read | One host's services: description, state (OK, WARN, CRIT, UNKNOWN), output, since when, acknowledged and in downtime. |
| `problems` | read | Hosts that are down or unreachable and services that aren't OK, worst first. `unhandledOnly` leaves out acknowledged ones and those in downtime. |
| `downtimes` | read | Id, site, host, service, start, end, author, comment and recurrence. `host` filters. |
| `acknowledge` | destructive | Acknowledges a host or service problem with a `comment`. `sticky` (default on) keeps it until the host or service is OK; `notify` (default off) tells the contacts. With a preview; no undo. |
| `schedule_downtime` | destructive | Puts a host (with its services) or one `service` into downtime from now for `durationMinutes` (1 to 43200, default 60), with a `comment`. The preview shows the target and the window. Undo ends it. |
| `end_downtime` | write | Ends a downtime by `id` and `site`, so its target notifies again. The preview shows what it covered. Undo schedules it again for the time it had left. |

Acknowledging and downtimes both stop notifications, and either can hide an
outage, so both are destructive. Ending a downtime only lets notifications
through again, so it's write. A problem that's already acknowledged, a
downtime that already covers the asked time, or one that has already ended
is reported as nothing to change; acknowledging a host that's UP or a
service that's OK is refused.

**Security.** The user and secret go in the `Authorization` header, and the
client won't follow a redirect to another host or from https to http. Host
names, service descriptions, downtime ids and site ids are checked before
any request, and filters are sent as structured Livestatus JSON, never as
text. Check output is cut at 500 characters and anything that looks like a
credential in it is redacted.

**Notes.** Checkmk answers a new downtime without its id, so the module
finds it by its target, comment and end to offer the undo; if it can't, the
downtime is created without one. Removing an acknowledgement over the API
needs Checkmk 2.4, so `acknowledge` has no undo: remove it in Checkmk.
