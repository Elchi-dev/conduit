# GitHub

Everything a maintainer does on github.com or GitHub Enterprise, with a
personal access token alone (no GitHub App to install): repositories and
their settings, branches and protection, files and commits, releases and
tags, pull requests and reviews, issues, labels and milestones, Actions
(runs, logs, workflows, secrets, variables), webhooks, collaborators and
teams, deploy keys, environments, organization members, search,
notifications and gists, plus generic REST and GraphQL actions for anything
else.

**Setup.** Create a token (Settings, Developer settings, Personal access
tokens), store it in the vault and pick it in the token field. A
fine-grained token is the safer choice: pick the repositories (or "All
repositories") and only the permissions of the areas below that you want
Conduit to manage. Organization actions need the token's resource owner to
be that organization. For GitHub Enterprise, set `api` to
`https://<host>/api/v3`; GraphQL then uses `https://<host>/api/graphql` and
release uploads go to the same host. An Enterprise server inside a WireGuard
network can be reached by attaching the connection to a
[network](../architecture/networks.md). `repos` lists the repositories to
watch by default (`owner/name`).

## Token permissions per area

Fine-grained permission names; "read" is enough for the read actions of an
area, "write" for the rest. Metadata (read) is always included.

| Area | Actions | Fine-grained permission | Classic scope |
| --- | --- | --- | --- |
| Repositories | `repo`, `create_repo`, `update_repo`, `set_topics`, `archive_repo`, `unarchive_repo`, `fork_repo` | Administration | `repo` |
| Deleting and transferring | `delete_repo`, `transfer_repo` | Administration (write) | `delete_repo`, `repo` |
| Branches | `branches`, `branch`, `create_branch`, `delete_branch`, `rename_branch` | Contents | `repo` |
| Branch protection | `branch_protection`, `set_branch_protection`, `delete_branch_protection` | Administration | `repo` |
| Files, commits, tags | `file`, `tree`, `put_file`, `delete_file`, `commits`, `commit`, `compare`, `tags`, `create_tag`, `delete_tag` | Contents | `repo` |
| Checks | `checks` | Checks, Commit statuses (read) | `repo` |
| Releases | `releases`, `release`, `create_release`, `update_release`, `delete_release`, `upload_release_asset`, `delete_release_asset` | Contents | `repo` |
| Pull requests | `pull_requests`, `pull_request`, `create_pr`, `update_pr`, `close_pr`, `reopen_pr`, `review_pr`, `review_comment`, `delete_review_comment`, `request_reviewers`, `remove_reviewers`, `update_pr_branch`, `merge` | Pull requests (merging also needs Contents write) | `repo` |
| Issues | `issues`, `issue`, `search_issues_in_repo`, `create_issue`, `update_issue`, `close_issue`, `reopen_issue`, `comment`, `comments`, `edit_comment`, `delete_comment`, `add_labels`, `remove_labels`, `assign`, `unassign`, `lock_issue`, `unlock_issue` | Issues (Pull requests for comments and labels on PRs) | `repo` |
| Labels and milestones | `labels`, `create_label`, `update_label`, `delete_label`, `milestones`, `create_milestone`, `update_milestone`, `delete_milestone` | Issues | `repo` |
| Actions | `runs`, `run`, `jobs`, `job_logs`, `rerun`, `rerun_run`, `rerun_job`, `cancel_run`, `workflows`, `dispatch_workflow`, `enable_workflow`, `disable_workflow`, `artifacts` | Actions | `repo`, `workflow` |
| Secrets | `secrets`, `set_secret`, `delete_secret` | Secrets (organization: Secrets on the organization) | `repo` (organization: `admin:org`) |
| Variables | `variables`, `set_variable`, `delete_variable` | Variables (organization: Variables on the organization) | `repo` (organization: `admin:org`) |
| Webhooks | `hooks`, `create_hook`, `update_hook`, `delete_hook`, `ping_hook`, `hook_deliveries` | Webhooks (organization: Webhooks on the organization) | `admin:repo_hook` (organization: `admin:org_hook`) |
| Collaborators and teams | `collaborators`, `add_collaborator`, `remove_collaborator`, `repo_teams`, `set_team_access`, `remove_team_access`, `org_teams` | Administration; Members (read) on the organization for teams | `repo`, `read:org` |
| Deploy keys | `deploy_keys`, `add_deploy_key`, `delete_deploy_key` | Administration | `repo` |
| Environments | `environments`, `set_environment`, `delete_environment` | Administration | `repo` |
| Organizations | `orgs`, `org_members`, `set_org_membership`, `remove_org_member` | Members on the organization | `read:org` / `admin:org` |
| Search | `search` | Metadata; Contents for code search | `repo` for private results |
| Notifications | `notifications`, `mark_notifications_read` | not available to fine-grained tokens | `notifications` |
| Gists | `gists`, `gist`, `create_gist`, `update_gist`, `delete_gist` | Gists (account permission) | `gist` |
| Generic | `api_read`, `api_write`, `api_delete`, `graphql_read`, `graphql_mutate` | whatever the call needs | whatever the call needs |

## Risk, previews and undo

Every action declares its risk, which the policy engine uses (by default
agents may read, writes ask, destructive actions ask more firmly):

- **read**: everything that only looks.
- **write**: changes that are normal maintenance and usually reversible:
  creating and editing, committing a file, opening and closing, labels,
  re-running a run that already ran, unarchiving.
- **destructive**: running a workflow on a branch or tag
  (`dispatch_workflow`: it runs that revision's code with the repository's
  secrets), cancelling a run in progress (`cancel_run`), setting a secret
  (`set_secret`: replacing one can break or redirect deploy credentials),
  deleting a file (`delete_file`), deleting a repository, branch, tag, release, label,
  milestone, webhook, environment, deploy key, secret or variable,
  transferring a repository, removing people or teams, merging, and the
  generic `api_write`, `api_delete` and `graphql_mutate`. So are changes to
  who can reach a repository or what guards it, whatever their names say:
  adding people, teams, organization members and deploy keys
  (`add_collaborator`, `set_team_access`, `set_org_membership`,
  `add_deploy_key`), branch protection and environment rules
  (`set_branch_protection`, `set_environment`), repository settings
  (`update_repo`: visibility and the name), archiving (`archive_repo`) and
  reviews (`review_pr`: an approval counts toward required reviews; a line
  comment alone is `review_comment`, a write).

Every write and destructive action (apart from the first-generation ones
listed below) supports a dry run, so an approval shows what will happen:
the before and after values of settings, the old and new text of a file,
what a branch or tag points at before it's deleted, the request of a
generic API call. Undo is offered where it's natural:

- Creating something undoes by deleting it (repository, branch, tag,
  release, asset, label, milestone, gist, deploy key, variable, line
  comment); deleting a branch, tag, label, deploy key or variable undoes by
  recreating it as it was.
- `put_file` and `delete_file` commit; their undo commits the previous
  content back (or deletes a file that was new). Files over 1 MB aren't kept
  for undo. `put_file` doesn't change GitHub Actions code (workflows, local
  actions, `action.yml`, the Dependabot config), because that code runs
  with the repository's secrets: open a pull request for a person to review.
- Settings changes (`update_repo`, `set_topics`, `set_branch_protection`,
  `update_issue`, `update_pr`, `update_label`, `update_milestone`,
  `update_release`, `update_hook`, `set_environment`, collaborator, team and
  membership changes) undo by restoring the previous values.
- `set_secret` is sensitive: the value is encrypted with a libsodium sealed
  box to the repository's, environment's or organization's public key
  before it leaves Conduit, and it's never written to the audit log,
  approvals or events. Secrets can't be read back, so it has no undo, and
  `delete_secret` can't be undone either. `create_hook` is sensitive too
  (its signing secret).
- Merging, transferring and deleting a repository, release or environment
  can't be undone from Conduit.

## Generic API

For anything the dedicated actions don't cover (rulesets, Pages, packages,
Dependabot, projects ...):

- `api_read` sends a GET (read), `api_write` a POST, PATCH or PUT and
  `api_delete` a DELETE. `api_write` is destructive, like `api_delete`: a
  generic write reaches what the dedicated actions rate destructive (merging
  a pull request, transferring or archiving a repository, changing its
  visibility or branch protection), so it can't be a cheaper way to do them. `path` must be an
  API path starting with `/` (absolute URLs, `//host`, `..` segments and
  whitespace are refused); the token is only ever sent to the configured API
  host. `query` is an object of string parameters and `body` any JSON. The
  answer has the status, the body (cut at 1 MB) and the `Link` header for
  paging.
- `graphql_read` parses the document with a GraphQL parser and runs it
  only if every operation in it is a query (fragments are fine); a
  `mutation` or `subscription` operation, or a document that doesn't parse,
  is refused. `graphql_mutate` runs anything else and is destructive, since
  mutations include deletes, merges and transfers.

## Limits

Lists are paginated and bounded: `limit` defaults to 30 and is capped at 300
(100 for search), and at most 10 pages are read. Job logs return at most the
last 2000 lines and 256 KB; patches in `commit`, `compare` and
`pull_request` are cut to 4 KB per file and 100 files; file contents are
shown up to 1 MB; gist files are cut to 64 KB. Answers are slimmed for
people and agents: API link fields and node ids are dropped and user objects
become their login.

## First-generation actions

These keep their original names, inputs and outputs:

| Action | Risk | Notes |
| --- | --- | --- |
| `repos` | read | Your repositories, most recently pushed first |
| `pull_requests` | read | Open PRs in a repo or your watched repos; with neither, every open PR you're involved in |
| `issues` | read | Pull requests are filtered out |
| `runs` | read | Recent workflow runs; `failedOnly` |
| `rerun` | destructive | Re-runs the failed jobs of a run |
| `create_issue` | write | Undo closes it |
| `close_issue`, `reopen_issue` | write | Each undoes the other |
| `comment` | write | Undo deletes the comment |
| `delete_comment` | destructive | |
| `merge` | destructive | Dry run shows branch, commits and check state; the merge is pinned to the head commit that was approved, so a later push isn't merged unseen |

Health shows the signed-in user, and turns degraded when fewer than 100 API
calls are left in the hour.

Recommended policy: let agents read; ask for writes; keep destructive
actions (which include `api_write`, `api_delete`, `graphql_mutate`,
`dispatch_workflow` and `set_secret`) on ask (destructive ones are by default).
