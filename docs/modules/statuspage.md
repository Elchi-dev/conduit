# Statuspage

Pages, components and incidents of Atlassian Statuspage, and posting
incidents, updating them and setting component status on the public page.

**Setup.** In Statuspage, open your avatar, API info, and create an API key;
store it in the vault and enter its `secret://` reference. The key acts with
its user's access to each page. Page, component and incident ids come from
`pages`, `components` and `incidents`.

| Action | Risk | Notes |
| --- | --- | --- |
| `pages` | read | Id, name and public address (the custom domain, or the statuspage.io one). |
| `components` | read | Id, name, status (`operational`, `degraded_performance`, `partial_outage`, `major_outage`, `under_maintenance`) and group. Groups are marked `isGroup`. |
| `incidents` | read | Newest first: name, status, impact, short link, affected components and the latest update. `unresolved` for open ones only; `limit` up to 100. |
| `create_incident` | destructive | Posts an incident with a name, a status (default `investigating`), an optional impact, a message (`body`) and component statuses. The preview shows the page, the exact public text, each component's change and whether subscribers are notified. |
| `update_incident` | destructive | Posts an update: a new status, impact, message or component statuses. Nothing is posted when the incident already matches and there's no message. |
| `set_component_status` | destructive | Shows one component in a new status without an incident. Undo sets the status it had. |

Everything that changes something is public on the status page the moment it
runs, so each change is destructive and has a preview. Subscribers (email,
SMS, webhooks and the page's other channels) are notified only when the input
sets `notify: true`; otherwise Conduit sends `deliver_notifications: false`,
and the preview says so.

**Security.** The key goes in the `Authorization` header, and the client won't
follow a redirect to another host or from https to http. Ids are checked
before they reach a request path, and the public text is checked before
anything is sent.

## Notes

- Names and messages are plain text: `<` and `>` are refused, so the page shows
  exactly what the preview showed.
- Component groups take their status from their components, so set those
  instead.
- Changing a component's status on its own posts no incident; whether
  Statuspage tells component subscribers about it follows the page's own
  settings.
