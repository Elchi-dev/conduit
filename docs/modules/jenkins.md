# Jenkins

A Jenkins controller through its REST API: jobs and folders with their
status, a job's health, parameters and recent builds, one build's result,
causes, parameters, changes and artifacts, the tail of a build's console,
the build queue, and starting builds (with parameters), stopping them and
cancelling queued ones.

**Setup.** Sign in as the user Conduit should act as, open the user menu →
*Security* → *API Token*, add a token and store it in the vault. Enter the
username and the controller's address, such as `https://ci.example.com`,
with its context path if it has one (`https://example.com/jenkins`). The
user's permissions decide what works: Overall/Read and Job/Read for reading,
Job/Build to start builds, Job/Cancel to stop them. For a self-signed
certificate, enter its SHA-256 `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `jobs` | read | Jobs and folders at the top (or in `folder`) with status from the job's ball color (success, failed, unstable, aborted, disabled, not built, and "building") and the last build. `search` and `problems` (only failed or unstable) narrow it. |
| `job` | read | Status, description, health, whether it's buildable or queued, the next build number, last, last successful and last failed builds, the last 10 builds, and parameter definitions with choices and defaults (the default of a password or credentials parameter, or of any parameter whose name contains password, secret, token, key or credential in any case, shows as `[hidden]`). |
| `builds` | read | The last `limit` builds (up to 50) with result, start and duration. |
| `build` | read | One build (`number`, or the last one): result or RUNNING, estimated time, agent, causes, parameters (values of password parameters and of parameters whose name looks secret, like `API_TOKEN` or `DEPLOY_KEY`, shown as `[hidden]`), commits and artifact paths. |
| `console` | read, sensitive | The last `lines` (up to 2000) of the console, with terminal colors removed and very long lines cut. Jenkins can't serve a log from its end, so the module streams through at most 32 MiB of it and says so when the log is longer. Logs can hold secrets Jenkins didn't mask, so the output never reaches the audit log. |
| `queue` | read | Waiting builds with their queue id, why they wait and since when (never their parameters). |
| `trigger_build` | destructive | Queues a build. A build runs the job's code with its credentials, so it's destructive. `parameters` are checked against the job's definitions: unknown names, values outside a choice list and non-boolean values for boolean parameters are refused, and so are password, credentials and file parameters (their defaults are used). The preview shows the build number and every parameter value that will be used. The answer has the queue id. No undo: use `stop_build` or `cancel_queued`. |
| `stop_build` | destructive | Aborts a running build (work in flight, such as a deploy, stops part way); the preview names it and when it started. |
| `cancel_queued` | write | Removes a waiting build from the queue by its id. It hasn't started, so nothing is interrupted (that's why it stays write). |

Jobs in folders are given as `folder/job`; paths copied from a URL
(`job/folder/job/name`) work too.

**CSRF.** Before a POST the module fetches a crumb from
`/crumbIssuer/api/json` and sends it in the header Jenkins names, keeping
the session cookie the crumb belongs to. When Jenkins refuses a crumb (its
session expired) a new one is fetched once. With no crumb issuer, POSTs go
without.

**Security.** The username and token go in basic auth; the client won't
follow a redirect to another host or from https to http, and POSTs follow no
redirects at all. Every part of a job path is checked against Jenkins'
naming rules (no `/`, `..`, `?`, `%` and the like) and escaped before it's
put in a URL; build numbers and queue ids are integers.
