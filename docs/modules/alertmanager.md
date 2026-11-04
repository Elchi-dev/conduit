# Alertmanager

Firing alerts, receivers and silences of a Prometheus Alertmanager, and
creating or expiring silences, through its v2 API.

**Setup.** Enter the Alertmanager's address, such as
`http://alertmanager:9093`. Alertmanager asks for no credentials by
default; if its web config sets basic auth, enter the user and store the
password in the vault, or store a bearer token if a proxy in front asks for
one. For a self-signed certificate, set `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `status` | read | Version, uptime, cluster state, name and peers. |
| `alerts` | read | Active alerts, newest first, at most 500: name, state, since when, labels, summary and description, receivers, fingerprint and a link to the source. `includeSilenced` and `includeInhibited` add those; `labels` filters by exact label values. |
| `receivers` | read | The receivers' names. |
| `silences` | read | Active and pending silences with their matchers, start, end, author and comment; `includeExpired` adds expired ones. |
| `create_silence` | destructive | Mutes the alerts matching every matcher for `durationMinutes` (1 to 43200, default 120), with a `comment`. The preview shows the matchers and the time. Undo expires it. |
| `expire_silence` | write | Ends a silence by id, so its alerts notify again. The preview shows what it covered. Undo silences the same matchers for the time it had left. |

A silence stops every notification for what it matches, and a broad or long
one can hide an outage, so creating one is destructive whatever its
matchers. Expiring one only lets notifications through again, so it's write.
An active silence with the same matchers that already lasts as long, or a
silence that has already expired, is reported as nothing to change.

**Security.** Credentials go in the `Authorization` header, and the client
won't follow a redirect to another host or from https to http. Matchers are
checked before any request: label names as Prometheus spells them, values
of bounded length, regular expressions that compile, and at least one
positive matcher. Silence ids must be plain identifiers before they reach a
request path. The status answer is decoded field by field, so the
configuration (with receiver passwords and webhook URLs) is never read, and
alert links lose any user and password.

**Notes.** Grafana's own alerting has its silences in the
[Grafana](grafana.md) module; Prometheus queries, targets and alerts are in
[Metrics](metrics.md).
