# Opsgenie

Alerts, notes, on-call schedules and who's on call in Opsgenie, and
acknowledging and closing alerts.

**Setup.** In Opsgenie, open Settings, Integrations, add an API integration
and copy its API key; store it in the vault and enter its `secret://`
reference. Give the integration read access, plus create and update access
for changes. Set `region` to `eu` if you sign in at app.eu.opsgenie.com.

| Action | Risk | Notes |
| --- | --- | --- |
| `alerts` | read | Newest first: id, short number, message, status, priority, acknowledged, snoozed, count, tags, created and last occurred. Open ones unless `status` is `closed` or `all`; `priority` filters; `limit` up to 100. |
| `alert` | read | One alert by id or short number, with its description, details, entity, integration and how long it took to acknowledge and close. |
| `acknowledge_alert` | destructive | Stops the alert's notifications and escalation to further people. Optional `note`. Undo unacknowledges it. |
| `unacknowledge_alert` | write | Takes the acknowledgement off an open alert, so notifications and escalation go on. Undo acknowledges it again. |
| `close_alert` | destructive | Closes the alert: notifications and escalation stop even if the problem goes on. Optional `note`. |
| `add_note` | write | Adds a note to an alert. |
| `schedules` | read | Schedules with their team, time zone and whether they're on. |
| `on_call` | read, sensitive | Who's on call now in each enabled schedule, or in one `schedule`, by Opsgenie user name (their email address). |

Changes are recorded as `Conduit`, or `Conduit (for …)` with `by`, never on a
person's name, with `Conduit` as the source. An alert that's already
acknowledged or closed is left as it is. Each change has a preview.

**Security.** The key goes in the `Authorization` header to the region's fixed
API host, and the client won't follow a redirect to another host or from
https to http. Alert and schedule ids are checked before they reach a request
path, and the change goes to the alert's own id from Opsgenie. Alert text is
redacted of anything that looks like a credential; owners and who
acknowledged or closed an alert are left out, and who's on call is only in
the sensitive `on_call`.

## Notes

- Opsgenie carries out alert changes in the background, usually within
  seconds; the answer has the request id.
- Closed alerts can't be reopened, and notes can't be removed through the API.
- Atlassian is retiring Opsgenie in favour of Jira Service Management and
  Compass; the API keeps working until the shutdown date Atlassian announced.
