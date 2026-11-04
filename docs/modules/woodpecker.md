# Woodpecker CI

Pipelines on a Woodpecker CI server (Woodpecker 2 and 3): their status,
workflows and steps, step logs, and restarting or cancelling them. Often
paired with [Gitea and Forgejo](gitea.md).

**Setup.** In Woodpecker, open your user menu, Personal Access Token, copy
it into the vault and enter its reference with the server address
(`https://ci.example.com`).

| Action | Risk | Notes |
| --- | --- | --- |
| `repos` | read | Repositories the user can see, active ones first |
| `pipelines` | read | Recent pipelines (up to 50), optionally of one branch |
| `pipeline` | read | One pipeline's workflows and steps, with step ids, states, exit codes and durations |
| `logs` | read, sensitive | The end of one step's log (default 200 lines, at most 2000 and 256 KB). The step is its name, `workflow/step`, or its id. Kept out of the audit log |
| `restart` | destructive | Runs the pipeline again as a new one, so its code runs again with the repository's secrets. Preview first |
| `cancel` | write | Stops a pending, running or blocked pipeline. Preview first |

`repo` is always `owner/name` and numbers must be positive, so input can't
reach other API paths. Redirects to another host are refused.
