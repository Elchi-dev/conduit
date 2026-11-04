# UptimeRobot

UptimeRobot monitors through the API v2: status and uptime ratios, recent
downtime, pausing and resuming one monitor, creating a simple HTTP monitor
and deleting a monitor.

**Setup.** Copy the Main API key (My Settings, API Settings) into the vault.
The read-only API key works too, for the read actions only; changes are
then refused with a clear message.

| Action | Risk | Notes |
| --- | --- | --- |
| `monitors` | read | Monitors (up to 500; `search` by name or URL, `status` up, down or paused) with type, interval, status and uptime over 1, 7 and 30 days. |
| `monitor` | read | One monitor `id` with uptime and its latest 10 events (down, up, paused, started) with reason. |
| `recent_downs` | read | The latest down events across monitors (or of monitor `id`), newest first, with duration, reason and whether the outage is still going on (`limit` up to 100). |
| `pause_monitor` | write | Pauses **one** monitor `id`: it stops checking and alerting until resumed. The preview shows its status; pausing an already paused monitor does nothing. Pausing every monitor isn't offered. Undo resumes it. |
| `resume_monitor` | write | Resumes a paused monitor. Undo pauses it again. |
| `create_monitor` | write | Creates an HTTP(S) monitor of a `url` named `name`, checked every `interval` seconds (60 to 86400, 300 by default; the free plan's minimum is 300). It gets no alert contacts; add them in UptimeRobot. A URL with credentials in it is refused. Undo deletes it. |
| `delete_monitor` | destructive | Deletes a monitor with its uptime history and logs, for good. The preview shows what goes. |

**Security.** UptimeRobot v2 takes the key only in the form body; the
client follows redirects only within the same host and never from https to
http. Its error answers echo the key back, so only the error message is
passed on, redacted. Monitored URLs are shown without credentials or query
string, and heartbeat monitors' push URLs (which act as a secret) aren't
shown. Monitor IDs are integers, and names, URLs, intervals, searches and
limits are checked before they reach a request.
