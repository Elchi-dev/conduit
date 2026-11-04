# Azure DevOps

An Azure DevOps organization through its REST API (version 7.1): projects,
Git repositories and pull requests, pipelines and their runs (builds), and
Boards work items.

**Setup.** In Azure DevOps open User settings, Personal access tokens, and
create a token for the organization with an expiry and only the scopes you
need: **Code** (Read; Read & write to comment and complete pull requests),
**Build** (Read; Read & execute to queue and cancel), **Work Items** (Read;
Read & write to create, change and delete). Store it in the vault, enter
the organization name (as in `dev.azure.com/<organization>`) and, if you
like, a default project; every action that works in a project takes a
`project` that overrides it.

| Action | Risk | Notes |
| --- | --- | --- |
| `projects` | read | Projects with state, visibility and last update. |
| `repositories` | read | A project's Git repositories with default branch, size and link. |
| `pull_requests` | read | Pull requests in one `repo` or the whole project (`status` active by default, or completed, abandoned, all), with author, branches, merge status and every reviewer's vote. |
| `pull_request` | read | The above plus the description and the branch policies evaluated for it (builds, minimum reviewers, …) with their status and whether they block. |
| `comment_pull_request` | write | Starts a comment thread; reviewers are notified. |
| `complete_pull_request` | destructive | Completes (merges) an active, published pull request with `strategy` (noFastForward, squash, rebase, rebaseMerge), optionally deleting the source branch and with a merge commit `message`. The commit it completes is pinned to the one seen, so a push in between makes Azure DevOps refuse it. Policies are **never bypassed**: when blocking policies aren't met yet, the completion is queued until they are. The preview shows branches, strategy, every vote (rejections called out), the merge status (conflicts called out) and the blocking policies not met. No undo. |
| `pipelines` | read | Pipeline (build) definitions with folder, repository, default branch and whether queueing is enabled. `search` matches names. |
| `builds` | read | Recent runs (of one `pipeline` by id or name, on one `branch`) with status, result, commit, reason and who requested them. |
| `build` | read | One run with its stages and jobs and up to 20 failed tasks with their error messages and log ids. |
| `build_log` | read, sensitive | The last `lines` (up to 2000) of a log: the given `log`, otherwise the first failed task's, otherwise the run's last log. Only those lines are requested. Logs can hold secrets the run printed, so the output never reaches the audit log. |
| `queue_build` | destructive | Runs a pipeline (by id or exact name) on `branch` (the pipeline's default unless given) with optional queue-time `variables` and YAML runtime `parameters`. It runs the repository's code with the pipeline's service connections and secrets, hence destructive. The preview names the pipeline, branch and every value. Refused when the pipeline is disabled. |
| `cancel_build` | destructive | Cancels a queued or running run; work in flight, such as a deploy, stops part way. |
| `query_work_items` | read | Runs a WIQL `SELECT` (only SELECT is accepted; WIQL has no statements that change anything) and returns up to `limit` (200) work items with type, title, state, assignee name, tags and link. Flat and link queries both work. |
| `work_item` | read | Type, title, state, reason, assignee, creator, area, iteration, tags and the description (and repro steps for bugs) as plain text. Never e-mail addresses. |
| `create_work_item` | write | Creates a work item of `type` with title and optional description (stored as text, HTML escaped), assignee, area and iteration paths and tags. Undo deletes it to the recycle bin. |
| `update_work_item_state` | write | Moves a work item to another `state`, checked against that type's states (and spelled as Azure DevOps spells it). The change is tied to the revision seen, so an edit in between makes it fail rather than overwrite. Undo moves it back. |
| `delete_work_item` | destructive | Moves a work item to the project's recycle bin; it's never destroyed. Undo restores it. |
| `restore_work_item` | write | Restores a work item from the recycle bin; undo deletes it again. |

**Security.** The token is sent with basic auth only to `dev.azure.com`;
the client sends `X-TFS-FedAuthRedirect: Suppress` so a refused token gives
an error rather than a sign-in page, treats a sign-in page as a refusal,
and won't follow a redirect to another host. Organization, project,
repository and work item type names are checked against Azure DevOps'
naming rules (no `/`, `\`, `?`, `#`, `%`, `..` and the like) and escaped
before they're put in a URL; ids are integers and branch names are checked.
