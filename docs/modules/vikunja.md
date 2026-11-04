# Vikunja

Your Vikunja projects and tasks: what's due today or overdue, any filter,
and adding, completing, reopening, editing and deleting tasks.

**Setup.** In Vikunja, open Settings, API Tokens, and create a token with
the task and project permissions you want an agent to have, then store it
in the vault. Enter Vikunja's address, such as `https://tasks.example.com`.
"Today" uses your Vikunja time zone unless you set `timezone` (for example
`Europe/Berlin`).

| Action | Risk | Notes |
| --- | --- | --- |
| `projects` | read | Every project; archived ones last and marked. |
| `today` / `overdue` | read | Open tasks due today, or before today. |
| `tasks` | read | Tasks matching a Vikunja `filter` (`priority >= 3`, `due_date < now+7d`, `labels in 4`), in a `project`, or matching `search` words. Without a filter, open tasks only unless `includeDone` is set; with one, the filter decides (add `done = false`). Up to `limit` (default 50, at most 200). |
| `task` | read | One task with its description. |
| `create_task` | write | In a `project` (id), with `title`, `description`, `due` (`YYYY-MM-DD` for midnight in your time zone, or an RFC 3339 time) and `priority` (0 unset to 5 do now). Undo deletes it. |
| `mark_done` | write | Undo reopens it. A repeating task moves to its next date instead, and undo puts the old date back. |
| `mark_undone` | write | Reopens a done task; undo marks it done again. |
| `update_task` | write | Changes only the fields given (an empty `due` clears it). The preview shows old and new values; undo restores the old ones. |
| `delete_task` | destructive | With a preview. Vikunja can't restore a deleted task, its comments or attachments. |

Vikunja replaces a whole task on every update, so the module reads the task
first and sends it back with only the given fields changed.

**Security.** The token goes in the `Authorization` header and the client
won't follow a redirect to another host. Task and project ids must be
positive numbers before they reach a request path. For a self-signed
certificate, pin its SHA-256 `fingerprint`.
