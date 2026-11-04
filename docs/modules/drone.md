# Drone CI

Builds on a Drone server: repositories, builds with their stages and steps,
step logs, and restarting, cancelling or promoting builds.

**Setup.** In Drone, open your user settings and copy Your Personal Token
into the vault. Enter its reference with the server address
(`https://drone.example.com`, with a path if Drone is served under one).

| Action | Risk | Notes |
| --- | --- | --- |
| `repos` | read | Repositories the user can see, active ones first, with their latest build |
| `builds` | read | Recent builds (up to 50), optionally of one `branch` |
| `build` | read | One build's stages and steps with numbers, states, exit codes and durations |
| `logs` | read, sensitive | The end of one step's log (default 200 lines, at most 2000 and 256 KB). The step is its name, `stage/step`, or `stage.step` numbers like `1.2`. Kept out of the audit log |
| `restart` | destructive | Runs a finished build again as a new one, so its code runs again with the repository's secrets. Preview first |
| `cancel` | destructive | Stops a pending, running or blocked build; steps in progress are killed. Preview first |
| `promote` | destructive | Promotes a successful build to a deployment `target` (e.g. `production`): a new build runs that target's pipelines, which usually deploys. Preview first |

`repo` is always `owner/name`, numbers must be positive and targets are
plain names, so input can't reach other API paths. Redirects to another
host are refused.
