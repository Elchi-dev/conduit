# GitLab

Projects, merge requests, issues and pipelines on gitlab.com or a
self-managed GitLab.

**Setup.** Create a personal access token with `read_api` (or `api` for
retries and issues), store it in the vault, and set `url` for your own
GitLab. `projects` lists projects to watch (`group/project`).

| Action | Risk | Notes |
| --- | --- | --- |
| `projects` | read | Projects you're a member of |
| `merge_requests` | read | Open MRs in a project or your watched projects; with neither, the ones assigned to you |
| `issues` | read | Same scoping as merge requests |
| `pipelines` | read | `failedOnly` |
| `retry_pipeline` | write | Retries failed jobs |
| `create_issue` | write | Undo closes it |
| `close_issue`, `reopen_issue` | write | Each undoes the other |
