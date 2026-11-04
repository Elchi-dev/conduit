# Datadog

A Datadog organization through its API: monitors and their state, what's
alerting now, muting one monitor for a while and unmuting it, incidents,
posting events, dashboards and SLO status.

**Setup.** In Organization settings create an API key and an application
key and store both in the vault. Scope the application key to what you
use: `monitors_read`, `monitors_downtime` (mute and unmute),
`incident_read`, `events_read` (posting events needs only the API key),
`dashboards_read` and `slos_read`. Pick your site: the part after `app.`
in the address you sign in at, one of `datadoghq.com`,
`us3.datadoghq.com`, `us5.datadoghq.com`, `datadoghq.eu`,
`ap1.datadoghq.com`, `ap2.datadoghq.com` or `ddog-gov.com`. Anything else
is refused, so the keys only ever go to `api.<site>`.

| Action | Risk | Notes |
| --- | --- | --- |
| `monitors` | read | Monitors (filtered by `name` and monitor `tags`) with state, type, tags, priority and whether a downtime mutes them. |
| `monitor` | read | One monitor's query, message, the state of each group and when it last triggered, and its active downtimes. |
| `triggered_monitors` | read | Monitors in Alert, Warn or No Data now, with when they triggered. |
| `mute_monitor` | write | Schedules a downtime for **one** monitor `id`, for `minutes` (1 to 10080, 60 by default), on a `scope` such as `host:web-1` or `env:prod`, or on all of that monitor's groups only when `allGroups` is set. Muting every monitor, a wildcard scope (`*`, `host:web-*`) and indefinite mutes are refused. The preview shows the monitor, its state, the scope and the end time. Undo cancels the downtime. |
| `unmute_monitor` | write | Cancels a `downtime` by id, or every active downtime that names monitor `id`. A monitor muted by a tag-based downtime is reported as such, not unmuted. |
| `incidents` | read | Recent incidents with number, title, severity, state and customer impact. |
| `post_event` | write | Posts an event (`title`, `text`, `alertType`, `priority`, `tags`, `aggregationKey`), for example a deploy marker. The preview shows the event; events can't be deleted. |
| `dashboards` | read | Dashboards with title, link and last change (`search` by title). Never their authors' e-mail. |
| `slos` | read | SLOs (by `search` query) with type, tags and, for each time window, target, current value, error budget left and state. |

**Security.** The keys go in the `DD-API-KEY` and `DD-APPLICATION-KEY`
headers. Go forwards custom headers on redirects, so the client follows
redirects only within the same host and never from https to http. Monitor
ids are integers, downtime ids UUIDs, and scopes, tags and search queries
are checked before they reach a request.
