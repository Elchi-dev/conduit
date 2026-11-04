# YouTrack

Projects and issues in YouTrack, cloud or self-hosted: finding issues with
YouTrack's query language, creating issues, commenting and applying
commands.

**Setup.** In YouTrack, open your profile, Account security, Tokens, and
create a permanent token with YouTrack in its scope; store it in the vault
and enter its `secret://` reference. Enter your YouTrack address, such as
`https://example.youtrack.cloud` or `https://youtrack.example.com`. For a
self-signed certificate, set `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `projects` | read | Short name, name, description. `archived` includes archived projects. |
| `issues` | read | Issues matching a `query` (`for: me #Unresolved`, `project: PRJ State: Open sort by: updated`): id, summary, project, resolved, fields (state, priority, assignee, tags …), updated, link. `limit` and `skip` page through them. |
| `issue` | read | Everything above plus description, reporter and the 20 latest comments. |
| `create_issue` | write | Creates an issue in a project (by short name) with a summary and Markdown description. Undo deletes it. |
| `comment` | write | Adds a Markdown comment. The preview names the people it @mentions, who are notified. Undo deletes it. |
| `apply_command` | destructive | Runs a YouTrack command on an issue (`State In Progress`, `for me`, `Priority Critical`, `tag Backend`), optionally with a comment, optionally `silent`. YouTrack checks the command first; the preview lists what it will do. |
| `delete_comment` | destructive | Deletes a comment. |
| `delete_issue` | destructive | Deletes the issue for good. The preview shows it. |

Every changing action except `delete_comment` has a preview.

**Security.** The token goes in the `Authorization` header, and the client
won't follow a redirect to another host or from https to http. Issue,
project and comment ids must match YouTrack's forms (`PRJ-12`, `4-17`) before
they reach a request path; queries travel as URL parameters. Email addresses
are never requested.

## Notes

- `apply_command` is destructive because a command can change any field,
  move or delete the issue; it has no undo.
- Wildcard mentions such as `@all` are refused in comments and command
  comments.
