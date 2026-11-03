# GitHub

Repositories, pull requests, issues and Actions runs on github.com or GitHub
Enterprise.

**Setup.** Create a fine-grained personal access token (Settings, Developer
settings) for the repositories you want, with read access to contents,
issues, pull requests and actions; add write access only for what agents may
change. Store it in the vault and pick it in the token field. For Enterprise,
set `api` to `https://<host>/api/v3`. `repos` lists the repositories to
watch by default (`owner/name`).

| Action | Risk | Notes |
| --- | --- | --- |
| `repos` | read | Your repositories, most recently pushed first |
| `pull_requests` | read | Open PRs in a repo or your watched repos; with neither, every open PR you're involved in |
| `issues` | read | Pull requests are filtered out |
| `runs` | read | Recent workflow runs; `failedOnly` |
| `rerun` | write | Re-runs the failed jobs of a run |
| `create_issue` | write | Undo closes it |
| `close_issue`, `reopen_issue` | write | Each undoes the other |
| `comment` | write | Undo deletes the comment |
| `delete_comment` | destructive | |
| `merge` | destructive | Dry run shows branch, commits and check state; the merge is pinned to the head commit that was approved, so a later push isn't merged unseen |

Health shows the signed-in user, and turns degraded when fewer than 100 API
calls are left in the hour.

Recommended policy: let agents read; ask for issues and comments; keep
`merge` on ask (it is by default as a destructive action).
