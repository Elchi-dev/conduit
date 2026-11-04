# TeamCity

A TeamCity server through its REST API: projects, build configurations with
their parameters, queued, running and finished builds, the tail of a
build's log, and queueing or cancelling builds.

**Setup.** Sign in as the user Conduit should act as, open your profile,
*Access Tokens*, create a token and store it in the vault. Enter the
server's address, such as `https://teamcity.example.com`, with its context
path if it has one. The user's permissions decide what works: viewing a
project for reading, *Run build* to queue builds, *Cancel build* to cancel
them. For a self-signed certificate, enter its SHA-256 `fingerprint`.
Health shows the signed-in user and the TeamCity version.

| Action | Risk | Notes |
| --- | --- | --- |
| `projects` | read | Id, name, parent, description, whether it's archived. |
| `build_configurations` | read | Id, name, project and whether it's paused, of one `project` (with its subprojects) or all. |
| `build_configuration` | read | One build configuration with its parameters: type (text, select, checkbox, password), the choices of a select, and defaults (redacted where they look like a credential). The default of a password parameter, or of any parameter whose name contains password, secret, token, key or credential, shows as `[hidden]`. |
| `builds` | read | Builds, newest first (up to 100), of one `buildType` or the whole server, by `state` (`queued`, `running`, `finished` or `any`) and `branch`: id, number, state, status and status text, branch, who or what triggered it, when it was queued, started and finished, progress while running and why it waits while queued. |
| `build` | read | One build by its id: everything `builds` shows plus agent, revisions, and who cancelled it with their comment. |
| `build_log` | read, sensitive | The last `lines` (default 200, up to 2000) of a build's log, with terminal colors removed, anything that looks like a credential redacted and very long lines cut (a line cut while it's read loses the token-like text before the cut, so half a credential isn't kept). At most 32 MiB of a log is read. Kept out of the audit log. |
| `trigger_build` | destructive | Queues a build of a build configuration, on `branch` if given, with `parameters`. A build runs the configuration's code with its credentials and can deploy. Only declared parameters are accepted; select values must be one of the choices, checkbox values become the configured checked or unchecked value, password parameters are refused (their stored value is used), and so is
a value with a parameter reference such as `%deploy.password%` or
`%vault:…%`, which TeamCity would resolve when the build starts (write
`%%` for a literal `%`; the configuration's own choices and checkbox
values are exempt). The preview shows the branch and every value passed, with secret-looking names hidden. |
| `cancel_build` | destructive | Removes a queued build from the queue or stops a running one, with the comment "Cancelled through Conduit". A finished build answers "nothing to change". |

Builds are named by their id (the number TeamCity shows in a build's
address), not their build number, since numbers repeat across
configurations.

**Security.** The token goes in the `Authorization` header, and the client
won't follow a redirect to another host or from https to http. Ids, branch
names and parameter names are checked before they reach a request path or
locator (a branch can't start with `-`, `+`, `/` or `.`, or hold `..`); status texts, descriptions and comments are redacted before
they're cut.

**Notes.** Without `branch`, `builds` covers every branch. Multi-select
parameters are passed as given, without checking each value.
