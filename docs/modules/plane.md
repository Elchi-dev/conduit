# Plane

Projects, states and work items (issues) in Plane, cloud or self-hosted, and
creating, updating and commenting on them.

**Setup.** In Plane, open Profile settings, Personal access tokens (or
Workspace settings, API tokens) and create a key; store it in the vault and
enter its `secret://` reference. Enter the workspace slug, the part after the
host in Plane's address (`app.plane.so/<slug>/`). Leave the address as
`https://api.plane.so` for Plane Cloud, or enter your instance's address,
such as `https://plane.example.com`. For a self-signed certificate, set
`fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `projects` | read | Id, name, identifier, description, members, archived. |
| `states` | read | A project's states and their groups (backlog, unstarted, started, completed, cancelled). |
| `issues` | read | A project's work items, newest first: key (`WEB-12`), name, state, priority, dates, assignee count. Pass the `cursor` an answer returns for the next page. |
| `issue` | read | Everything above plus the description and comments. |
| `create_issue` | write | Adds a work item with name, plain-text description, state (by name), priority and due date (`YYYY-MM-DD`). Undo deletes it. |
| `update_issue` | write | Changes the fields given; set `state` to move it. Says "nothing to change" when it already matches. Undo puts the old values back. |
| `comment` | write | Adds a plain-text comment. Undo deletes it. |
| `delete_comment` | destructive | Deletes a comment. |
| `delete_issue` | destructive | Deletes a work item with its comments. The preview shows it. |

Every changing action except `delete_comment` has a preview.

**Security.** The key goes in the `X-API-Key` header, and the client won't
follow a redirect to another host or from https to http. Project, work item
and comment ids must be UUIDs before they reach a request path. Text is sent
as escaped HTML, so it can't carry markup or mention tags. Email addresses
are never decoded.

## Notes

- The module uses Plane's work-items API and falls back to the older issues
  API on servers that don't have it yet.
- Undoing a description change puts back the old text without its
  formatting.
