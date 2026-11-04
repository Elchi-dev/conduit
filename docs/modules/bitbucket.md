# Bitbucket

Bitbucket Cloud through its REST API 2.0: a workspace's repositories, pull
requests (reading, commenting, approving, merging with a preview,
declining) and Pipelines (runs, step status, the tail of a step's log,
running and stopping pipelines).

**Setup.** Enter the workspace ID (as in `bitbucket.org/<workspace>/`) and
store one of these in the vault:

- an **Atlassian API token** with Bitbucket scopes (Atlassian account
  settings, Security, API tokens): enter your account **email** as the
  username;
- a legacy **app password** (being retired by Atlassian): enter your
  Bitbucket **username**;
- a **workspace, project or repository access token**: leave the username
  empty; it's sent as a bearer token.

Read scopes for repositories, pull requests and pipelines cover the read
actions; commenting, approving, merging and declining need pull request
write; running and stopping pipelines need pipeline write.

| Action | Risk | Notes |
| --- | --- | --- |
| `repositories` | read | The workspace's repositories (newest change first, up to 500) with main branch, project, language and privacy. `search` matches names. |
| `pull_requests` | read | A repository's pull requests (open unless `state` is `MERGED`, `DECLINED` or `SUPERSEDED`) with author, branches, comment and task counts. |
| `pull_request` | read | Description, participants with approvals and change requests, the destination's default merge strategy, source commit, and the size of the change (files, lines added and removed, conflicted files). |
| `comment` | write | Adds a Markdown comment; participants are notified. The preview shows the text. No undo: the notifications are already sent. |
| `approve` | destructive | Approves as the token's user; the approval counts toward merge checks like a person's review, so it's destructive. Undo removes the approval. |
| `unapprove` | write | Removes the token user's approval; undo approves again. |
| `merge` | destructive | Merges into the destination branch with `strategy` (the branch's default unless given, and only one the branch allows), optionally closing the source branch and with a commit `message`. The preview shows the branches, strategy, approvals, **change requests**, open tasks, draft state, conflicted files and the size of the change. If Bitbucket is still merging when it answers, the result says so. No undo. |
| `decline` | destructive | Declines an open pull request, with an optional message. Bitbucket Cloud can't reopen a declined pull request, hence destructive. |
| `pipelines` | read | Recent runs with number, UUID, status, branch, commit, custom pipeline, trigger, who started it and duration. |
| `pipeline` | read | One run (by UUID or build number) with each step's status and duration. |
| `pipeline_log` | read, sensitive | The last `lines` (up to 2000) of a step's log: the step given by name or UUID, otherwise the first failed step, otherwise the last one that started. At most the last 512 KiB of the log is fetched (with a Range request); terminal colors are removed and very long lines cut. Logs can hold secrets the run printed, so the output never reaches the audit log. |
| `run_pipeline` | destructive | Runs the branch's pipeline, or the `custom` pipeline from `pipelines.custom`, with optional `variables` (custom pipelines only). It runs the repository's code with its variables and deployment credentials, hence destructive. The preview names the branch, pipeline and every variable value, so keep secrets in repository variables rather than passing them here. |
| `stop_pipeline` | destructive | Stops a pending or running run (work in flight, such as a deploy, stops part way); refused once it's finished. |

Pipelines are given by UUID (with or without braces) or build number
(`42` or `#42`, looked up among the last 500 runs).

**Security.** Credentials go in the `Authorization` header and the client
won't follow a redirect to another host or from https to http. When
Bitbucket answers a log request with a redirect to its log storage, that
pre-signed link is fetched over https only and **without** credentials.
Repository slugs (a `workspace/repo` form must name the configured
workspace), pipeline and step UUIDs, pull request numbers and branch names
are checked before they reach a request; the repository search is limited
to characters that can't change Bitbucket's query.
