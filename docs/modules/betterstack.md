# Better Stack Uptime

Better Stack Uptime through its API: monitors and their status, incidents
(listing, acknowledging and resolving), who's on call and status pages.

**Setup.** Create an Uptime API token (Settings, API tokens; a team token)
and store it in the vault.

| Action | Risk | Notes |
| --- | --- | --- |
| `monitors` | read | Monitors (up to 1000; `status` narrows) with type, status, check frequency and when they were last checked, and counts by status. |
| `incidents` | read | Incidents of the last `days` (up to 90, 7 by default), unresolved only unless `includeResolved`, with name, cause, start, and when they were acknowledged and resolved (`limit` up to 100). Never who acknowledged or resolved them. |
| `acknowledge_incident` | write | Acknowledges an ongoing `incident`, recorded as `by` (Conduit by default), which stops its escalation. The preview shows the incident; an already acknowledged or resolved one is left alone. It can't be un-acknowledged. |
| `resolve_incident` | destructive | Resolves an `incident`: alerting and escalation for it stop even if the monitor is still failing, and it can't be reopened. The preview shows the incident. |
| `on_call` | read, sensitive | Who's on call now in each on-call calendar, with name and email (never phone numbers). Sensitive because it returns personal data. |
| `status_pages` | read | Status pages with their address and overall state. |

**Security.** The token goes as a Bearer token, and the client follows
redirects only within the same host and never from https to http.
Monitored and incident URLs are shown without credentials or query string,
and heartbeat monitors' URLs aren't shown. Incident IDs are numbers, and
statuses, days, limits and the `by` name are checked before they reach a
request.
