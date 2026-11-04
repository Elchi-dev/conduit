# Asana

Workspaces, projects and tasks in Asana, and creating, updating, completing
and commenting on tasks.

**Setup.** In Asana, open My settings, Apps, then Manage developer apps, and
create a personal access token; store it in the vault and enter its
`secret://` reference. The token acts as you, so it sees and changes what you
can.

| Action | Risk | Notes |
| --- | --- | --- |
| `workspaces` | read | Id, name, and whether it's an organization. |
| `projects` | read | Projects in a workspace (the only one when you have one): name, team, archived, link. `archived` lists archived projects instead. |
| `tasks` | read | Open tasks in a `project`, or the tasks assigned to you in a `workspace`: name, assignee, due date, projects, link. `completed` includes finished ones. Up to 100. |
| `task` | read | Everything above plus notes, tags and the 20 latest comments. |
| `create_task` | write | In a project, or in a workspace's My Tasks (assigned to you). Name, notes, due date (`YYYY-MM-DD`) and assignee (`me` or a user id). Undo deletes it. |
| `update_task` | write | Changes the fields given; an empty due date or assignee clears it. Says "nothing to change" when the task already matches. Undo puts the old values back. |
| `complete_task` | write | Marks the task complete. Undo reopens it. |
| `reopen_task` | write | Marks it incomplete. Undo completes it. |
| `comment` | write | Adds a plain-text comment. Undo deletes it. |
| `delete_comment` | destructive | Deletes a comment (only comments, never Asana's activity entries). |
| `delete_task` | destructive | Moves the task and its subtasks to Asana's trash. The preview shows the task. |

Every changing action has a preview.

**Security.** The token goes in the `Authorization` header, and the client
won't follow a redirect to another host or from https to http. Ids must be
Asana's numeric ids before they reach a request path. Email addresses are
never requested, so they don't reach answers or the audit log.

## Notes

- Comments notify the task's collaborators, as they do in Asana. Wildcard
  mentions such as `@everyone` are refused; plain-text comments can't
  @-mention people.
- A deleted task can be restored from Asana's trash in the app for 30 days.
