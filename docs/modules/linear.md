# Linear

Your Linear issues: what's assigned to you, search, details with comments,
and creating, commenting on and moving issues.

**Setup.** In Linear, Settings, Security & access, Personal API keys, create
a key. Store it in the vault and enter its `secret://` reference.

| Action | Risk | Notes |
| --- | --- | --- |
| `my_issues` | read | Your open issues (not done or canceled) |
| `search` | read | Full-text search, 25 results |
| `issue` | read | Description, state, assignee, last 20 comments; by identifier (`ENG-123`) |
| `create` | write | In a team, by its key (`ENG`). Undo archives it. |
| `archive` | write | |
| `comment` | write | Undo deletes the comment |
| `delete_comment` | destructive | |
| `set_state` | write | Moves an issue to another state of its team, by name (`In Progress`, `Done`). Preview shows before and after; undo moves it back. |

**Security.** A personal API key acts as you in every team you can see. On
plans that allow it, create the key with only the read and write scopes
you need, or use a separate member account that only belongs to the teams
Conduit should touch.
