# Instatus

Pages, components and incidents of Instatus status pages, and posting and
updating incidents.

**Setup.** In Instatus, open User settings, Developer settings, and copy your
API key; store it in the vault and enter its `secret://` reference. Page,
component and incident ids come from `pages`, `components` and `incidents`.

| Action | Risk | Notes |
| --- | --- | --- |
| `pages` | read | Id, name, public address and overall status (`UP`, `HASISSUES`, `UNDERMAINTENANCE`). |
| `components` | read | Id, name, status (`OPERATIONAL`, `DEGRADEDPERFORMANCE`, `PARTIALOUTAGE`, `MAJOROUTAGE`, `UNDERMAINTENANCE`) and group. |
| `incidents` | read | Name, status, when it started and was resolved, affected components and the latest update. `unresolved` for open ones only; `limit` up to 100. |
| `create_incident` | destructive | Posts an incident with a name, a status (default `INVESTIGATING`), a message and the affected components with their status. The preview shows the page, the exact public text, each component's change and whether subscribers are notified. |
| `update_incident` | destructive | Posts an update with a message, and optionally a new status and component statuses. The incident's components stay listed with their current status unless the input changes them. Nothing is posted when the incident already matches and there's no message. |

Posting is public on the status page at once, so each change is destructive
and has a preview. Subscribers are notified only when the input sets
`notify: true`; otherwise Conduit sends `notify: false`, and the preview says
so.

**Security.** The key goes in the `Authorization` header, and the client won't
follow a redirect to another host or from https to http. Ids are checked
before they reach a request path, and the public text is checked before
anything is sent.

## Notes

- Names and messages are plain text: `<` and `>`, control characters and
  invisible formatting characters (direction overrides, zero-width spaces)
  are refused.
- Instatus posts every update with a message, so a status change needs one.
