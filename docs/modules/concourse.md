# Concourse

A Concourse CI server through its API, signed in the way `fly login` is:
teams, pipelines, jobs and builds, starting a job's build, and pausing or
unpausing pipelines.

**Setup.** Use a local user (one from `CONCOURSE_ADD_LOCAL_USER`), ideally
one made for Conduit, and give it a role in the team: `viewer` for reading,
`pipeline-operator` or `member` to start builds and pause pipelines. Store
its password in the vault and enter the username, the server's address,
such as `https://ci.example.com`, and the `team` actions use unless they
name another (default `main`). Conduit trades the password for a bearer
token, keeps it in memory until it expires, and signs in again when needed.
For a self-signed certificate, enter its SHA-256 `fingerprint`. Health
shows the user, the Concourse version and the user's roles in the team.

| Action | Risk | Notes |
| --- | --- | --- |
| `teams` | read | Team names and ids, and which one is configured. Teams' auth settings are left out. |
| `pipelines` | read | A team's pipelines with whether they're paused (by whom, since when), archived or public, when they were last set, and instance vars for instanced pipelines. |
| `jobs` | read | A pipeline's jobs with their groups, whether they're paused or have new inputs, and their last finished and next build. |
| `builds` | read | The last `limit` builds (up to 100), newest first, of a pipeline or one `job`: id, number, job, status, start, end, duration and who started it. |
| `trigger_job` | destructive | Starts a new build of a job, which runs its tasks with the pipeline's credentials and can deploy. Refused for archived or paused pipelines, paused jobs and jobs with `disable_manual_trigger`. The preview names the job's last build and its status. |
| `pause_pipeline` | destructive | Pauses a pipeline: no new builds are scheduled and its resources stop being checked (running builds go on). Undo unpauses it. |
| `unpause_pipeline` | destructive | Unpauses a pipeline; jobs can start at once on versions that arrived while it was paused. The preview names who paused it. Undo pauses it again. |

Pausing a paused pipeline, or unpausing one that isn't, answers "nothing
to change".

**Security.** The password is sent only to the server's own token
endpoint, and the token only in the `Authorization` header of API
requests; the client won't follow a redirect to another host or from https
to http. Sign-in errors say only that the sign-in failed, never what the
server echoed. Team, pipeline and job names are checked before they reach
a request path.

**Notes.** Actions on instanced pipelines (ones with instance vars) are
refused; they're listed by `pipelines`. Users from an external provider
(GitHub, OIDC, LDAP) can't sign in this way; give Conduit a local user.
