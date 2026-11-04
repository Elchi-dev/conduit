# Healthchecks

Cron and heartbeat checks on Healthchecks.io or a self-hosted Healthchecks
server, through the Management API v3: checks with status and last ping,
status changes, pausing and resuming a check, pinging one, creating a check
and deleting one.

**Setup.** In the project's Settings, API Access, create an API key and
store it in the vault. Leave the address at `https://healthchecks.io`, or
enter your server (with a path if it's served under one). The read-only key
only lists checks (without their UUIDs, so nothing can act on them). For a
self-signed certificate, enter its SHA-256 `fingerprint`. One instance is
one project.

| Action | Risk | Notes |
| --- | --- | --- |
| `checks` | read | Checks (up to 500; `tags` narrows) with UUID, status (up, down, grace, paused, new, started), last and next expected ping, period or cron schedule, grace and tags, and counts by status. |
| `check` | read | One `check` (UUID) with description and how many integrations it notifies. |
| `flips` | read | When a check went down and came back up over the last `days` (up to 90, 7 by default), newest first, at most 100. |
| `pause_check` | write | Pauses **one** check: no alerts until its next ping, or until resumed when the check needs a manual resume (the preview says which). Undo resumes it. |
| `resume_check` | write | Resumes a paused check; its status becomes new until the next ping. Undo pauses it again. |
| `ping_check` | destructive | Sends a ping as the job would, to the check's own ping URL: `success` (the default) marks it up, which can hide a real outage; `fail` marks it down and alerts; `start` starts the run timer; `log` only records. An optional `message` (up to 1000 characters) is stored with the ping. The preview shows the status now. |
| `create_check` | write | Creates a check `name` expecting a ping every `timeout` seconds (a day by default) or on a cron `schedule` in `tz`, with `grace` (an hour by default), `tags`, a `description` and, with `allIntegrations`, every integration of the project. Undo deletes it. |
| `delete_check` | destructive | Deletes a check with its ping history, for good; the job's pings stop being received. The preview shows what goes. |

**Security.** The key goes in the `X-Api-Key` header. Go forwards custom
headers on redirects, so the client follows redirects only within the same
host and never from https to http. Pings go to the ping URL the server
gives for the check (`hc-ping.com` on Healthchecks.io), which must end in
the check's UUID, and never carry the API key. Ping URLs aren't shown, but
a check's UUID is enough to ping it, and UUIDs appear in output and in the
audit log. UUIDs, tags, schedules, time zones and limits are checked before
they reach a request.
