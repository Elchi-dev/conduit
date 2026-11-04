# GoCD

A GoCD server through its API: pipelines with their groups and last runs,
a pipeline's history, the stages and jobs of a run, running a pipeline
(with values for its environment variables), and pausing or unpausing it.

**Setup.** Sign in as the user Conduit should act as, open the user menu,
*Personal Access Tokens*, create a token and store it in the vault. Enter
the server's address, such as `https://gocd.example.com` (the `/go` path is
added, so `https://gocd.example.com/go` works too). The user's permissions
decide what works: view for reading, operate to run, pause and unpause.
Passing environment variables to a run also reads the pipeline's
configuration, which needs a user who administers its pipeline group. For
a self-signed certificate, enter its SHA-256 `fingerprint`. Health shows
the signed-in user and the GoCD version.

| Action | Risk | Notes |
| --- | --- | --- |
| `pipelines` | read | Every pipeline with its group, whether it's locked or paused (by whom and why), whether it comes from a config repository, and its last run's label, counter, trigger and stage statuses. |
| `pipeline_history` | read | A pipeline's last `limit` runs (up to 50), newest first: counter, label, when, what triggered it (and whether by hand), and each stage's status and result. |
| `stages` | read | The stages of one run (`counter`, or the latest) with their approval type, who approved them, and their jobs' state, result and schedule time. |
| `trigger_pipeline` | destructive | Schedules a run, checking materials for new revisions first unless `updateMaterials` is false. A run executes the pipeline's code with its credentials and can deploy. `variables` must be environment variables the pipeline declares; secure ones are refused (their stored value is used). A paused, locked or unschedulable pipeline is refused with the reason. The preview shows each value passed, with secret-looking names hidden. |
| `pause_pipeline` | destructive | Pauses a pipeline with an optional `reason`, so changes and timers stop starting it (runs in progress go on). Undo unpauses it. |
| `unpause_pipeline` | destructive | Unpauses a pipeline; it can run at once on changes that arrived while it was paused. The preview names who paused it. Undo pauses it again with the same reason. |

Pausing a paused pipeline, or unpausing one that isn't, answers "nothing
to change".

**Security.** The token goes in the `Authorization` header, and the client
won't follow a redirect to another host or from https to http. Pipeline
and variable names are checked before they reach a request path. Secure
variables are never read: only their names and the fact that they're
secure. Pause reasons and trigger messages are redacted before they're cut.

**Notes.** Variables declared only on an environment, stage or job aren't
offered for a run; declare them on the pipeline to pass them.
