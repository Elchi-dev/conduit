# Todoist

Your Todoist projects, labels and tasks (due today, overdue, or any Todoist
filter), and adding, completing, updating and deleting tasks. It uses
Todoist's unified API v1 (`https://api.todoist.com/api/v1`), which replaced
the retired REST v2 and Sync v9 APIs.

**Setup.** In Todoist, open Settings, Integrations, Developer, copy the API
token and store it in the vault. The token has full access to the account,
so keep writes on ask in your policies if an agent uses it.

| Action | Risk | Notes |
| --- | --- | --- |
| `projects` | read | Every project, with the inbox, favourites, parents and archived ones marked. |
| `labels` | read | Personal labels. |
| `today` / `overdue` | read | Open tasks due today, or past due. |
| `tasks` | read | Open tasks matching a Todoist `filter` (`today \| overdue`, `#Work & p1`, `@waiting`), or in a `project` (id) and/or with a `label`. Up to `limit` (default 50, at most 200). |
| `task` | read | One task with its full description. |
| `add_task` | write | `content`, optional `description`, `labels`, `priority` (1 urgent to 4 normal, as in the app), `due` in Todoist's words (`tomorrow 5pm`, `every monday`) and `project` (the inbox by default). The preview shows the task; undo deletes it. |
| `complete_task` | write | Checks a task off; undo reopens it. A recurring task moves to its next date instead, and undo puts the old date back. |
| `reopen_task` | write | Unchecks a completed task; undo completes it again. |
| `update_task` | write | Changes only the fields given. The preview shows them before and after; undo puts the old values back (an exact date, not a phrase read relative to now). |
| `delete_task` | destructive | With a preview. Todoist can't restore a deleted task, its subtasks or comments. |

Task output gives priority as the app shows it (`p1` is urgent; the API
counts the other way round), the project's name and a link to the task.
The account's email address is never returned.

**Security.** The token goes in the `Authorization` header and the client
won't follow a redirect to another host. Task and project ids must be plain
ids (letters, digits, `-` and `_`) before they reach a request path; filters
and label names travel as query parameters.
