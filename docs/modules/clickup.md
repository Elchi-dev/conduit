# ClickUp

Workspaces, spaces, lists and tasks in ClickUp, and creating, updating and
commenting on tasks.

**Setup.** In ClickUp, open Settings, Apps, and generate an API token (it
starts with `pk_`); store it in the vault and enter its `secret://`
reference. The token acts as you.

| Action | Risk | Notes |
| --- | --- | --- |
| `workspaces` | read | Id and name of each workspace the token reaches. |
| `spaces` | read | Spaces in a workspace (the only one when you have one) with their statuses. |
| `lists` | read | Lists in a space, in folders or on their own, with task counts. |
| `tasks` | read | Tasks in a list: name, status, priority, due date, assignees, link. `closed` includes closed tasks; `page` pages through them (`nextPage` says when there's more). |
| `task` | read | Everything above plus description, tags and the 20 latest comments. |
| `create_task` | write | Adds a task to a list with name, description (Markdown), status, priority (1 urgent to 4 low) and due date (`YYYY-MM-DD`). Undo deletes it. |
| `update_task` | write | Changes the fields given; setting `status` closes or reopens a task. Says "nothing to change" when the task already matches. Undo puts the old values back. |
| `comment` | write | Adds a comment without ClickUp's "notify all". Undo deletes it. |
| `delete_comment` | destructive | Deletes a comment. |
| `delete_task` | destructive | Deletes a task with its subtasks and comments. The preview shows the task. |

Every changing action except `delete_comment` has a preview.

**Security.** The token goes in the `Authorization` header, and the client
won't follow a redirect to another host or from https to http. List, space
and workspace ids must be numbers and task ids plain letters and digits
before they reach a request path. Assignees appear by user name; email
addresses are never decoded.

## Notes

- Wildcard mentions such as `@everyone` are refused in comments.
- Undoing a description change puts back the old text without its
  formatting.
- Custom task ids (`DEV-12`) aren't accepted; use the task's own id.
