# Gatus

Every endpoint on a Gatus status page with its health, latest result and
recent success rate, and one endpoint's results and events.

**Setup.** Enter the status page's address, such as `http://gatus:8080`.
Gatus asks for no credentials by default; if `security.basic` is set, enter
the user and store the plain password (not the bcrypt hash in the config)
in the vault, or store a bearer token if a proxy in front asks for one. For
a self-signed certificate, set `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `endpoints` | read | Key, group, name, healthy, and the latest result's status code, response time, hostname, time, failed conditions and errors, with the success rate of the last 20 checks. `failingOnly` and `group` filter. At most 500. |
| `endpoint` | read | One endpoint's results, newest first (`limit` 1 to 100, default 20), and its events (start, healthy, unhealthy), newest first. |

Health is ok when every endpoint's latest check passed, and degraded when
any failed.

**Security.** Credentials go in the `Authorization` header, and the client
won't follow a redirect to another host or from https to http. Endpoint
keys are checked before they reach a request path. Conditions and errors
are cut at 300 characters, lose any user and password in URLs, and have
anything that looks like a credential redacted.

**Notes.** The module only reads. Endpoints protected by OIDC alone can't
be read, since that sign-in needs a browser.
