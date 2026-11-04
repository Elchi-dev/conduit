# incident.io

Incidents, severities and statuses in incident.io, declaring incidents and
moving them to another status.

**Setup.** In incident.io, open Settings, API keys, and create a key that can
view incidents, plus create and edit incidents for changes; store it in the
vault and enter its `secret://` reference.

| Action | Risk | Notes |
| --- | --- | --- |
| `incidents` | read | Newest first: id, reference, name, status and its category, severity, mode, visibility, created, updated and link. Live ones (triage and active) unless `status` is `post-incident`, `closed` or `all`; `limit` up to 100. |
| `incident` | read | One incident with its summary, type, channel and timestamps. |
| `severities` | read | Id, name, rank and description, in rank order. |
| `statuses` | read | Id, name, category and description, in order. |
| `create_incident` | destructive | Declares an incident with a name, an optional summary, severity and status (by id or name) and `visibility` (`public` to the whole organization, the default, or `private`). `test` declares a test incident. The preview shows what is declared and that workflows run. |
| `update_status` | destructive | Moves an incident to another status (by id or name). The incident's channel is told only with `notifyChannel`. Undo sets the status it had. |

Declaring an incident opens its channel and runs your workflows, which can
page people and post announcements, so it's destructive. Status changes run
workflows too, so they're destructive as well; an incident already in the
asked status is left as it is.

**Security.** The key goes in the `Authorization` header, and the client won't
follow a redirect to another host or from https to http. Incident ids are
checked before they reach a request path, and the change goes to the
incident Conduit read. The creator and role assignments are left out, and
summaries are redacted of anything that looks like a credential.

## Notes

- Incidents can't be deleted through the API; use `test` to try things out.
