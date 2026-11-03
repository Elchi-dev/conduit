# Jira

Search, create, comment on and move Jira issues.

**Setup.** Enter your Jira address (`https://example.atlassian.net`, or your
Data Center URL), then either:

- **Jira Cloud:** the account's email and an API token (id.atlassian.com,
  Security, Create and manage API tokens), stored in the vault. Conduit uses
  REST API v3.
- **Jira Data Center or Server:** a personal access token (your profile,
  Personal Access Tokens), stored in the vault. Conduit uses REST API v2.

Conduit can do what that account can do; a dedicated account with access to
the right projects is a good idea for teams.

| Action | Risk | Notes |
| --- | --- | --- |
| `search` | read | JQL, up to 100 results: key, summary, status, type, assignee, priority, updated, link |
| `issue` | read | One issue, with its description as plain text |
| `create` | write | Project key, type (default Task), summary, description (paragraphs separated by blank lines). Undo deletes the new issue. |
| `delete_issue` | destructive | |
| `comment` | write | Undo deletes the comment. |
| `delete_comment` | destructive | |
| `transitions` | read | Where the issue can move from its current status |
| `transition` | write | To a status by name (`to`) or a transition id (`id`). Supports a dry run that names both statuses. Undo moves it back when the workflow allows going straight back; otherwise there is no undo. |

Issue keys and project keys are checked before they reach a URL, and a move
the workflow doesn't allow fails with the list of statuses the issue can go
to.

**Security.** The API token acts as the account it belongs to, including
deleting issues it may delete. Deleting is marked destructive, so agents
need approval under the default rules.
