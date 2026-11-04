# InfluxDB

An InfluxDB 2 server through its API: health, buckets, read-only Flux
queries, tasks with their runs, and enabling or disabling a task.

**Setup.** Enter the `url` (such as `https://influx.example.com:8086`), the
organization's name (`org`) and an API `token` stored in the vault. Create
a token with read access to the buckets you want to query and read access
to tasks; add write access to tasks only if Conduit should enable and
disable them. The token's permissions are the real boundary: Conduit's
Flux checks below catch mistakes and the obvious tricks, but a token that
can write buckets could in principle write through anything the checks
miss. For a self-signed certificate, enter its SHA-256 `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `health` | read | Status (`pass` or `fail`), version and commit. |
| `buckets` | read | Buckets with ID, type (user or system), retention in seconds and creation time, up to 100. |
| `query` | read, sensitive | One Flux query, at most 15 seconds and 1000 rows (8 MB). Each table's rows come back as rows of the union of the columns. Results stay out of the audit log. |
| `tasks` | read | Tasks with status (active or inactive), schedule (`every` or `cron`), last completed time, last run status and error (redacted and clipped). Never the task's Flux. |
| `task_runs` | read | A task's last 20 runs with status and times. |
| `enable_task` | write | Sets a task active. The preview shows the status before and after. Undo disables it again (when the call changed anything). |
| `disable_task` | write | Sets a task inactive; a run in progress finishes. Undo enables it again. |

**What a query may do.** Imports must be at the top and on an allow list
of packages that only compute: `array`, `strings`, `regexp`, `math`,
`date`, `timezone`, `dict`, `types`, `join`, `interpolate`, `universe`,
`runtime`, `system`, `sampledata`, `influxdata/influxdb/schema`,
`influxdata/influxdb/v1`, `experimental` and the `experimental/aggregate`,
`array`, `table`, `query` and `date/boundaries` packages. Everything that
writes or reaches outside is left out, among them `http` and
`experimental/http` (`http.post`), `sql` (`sql.to`, `sql.from`),
`influxdata/influxdb/secrets`, `influxdata/influxdb/monitor`, `csv`
(`csv.from(file:)`), `experimental/csv`, `experimental/prometheus`,
`experimental/mqtt`, `socket` and the notification packages (`slack`,
`pagerduty`, `contrib/...`). With strings and comments blanked, `to` is
refused wherever it's used as a value (`to(...)`, `experimental.to`,
`universe.to`, an alias such as `w = to`), and so are `host:` and
`token:` arguments, which point `from()` and similar functions at another
server. String interpolation (`"${...}"`) is refused, since it would hide
an expression inside a string.

**Security.** The token goes in `Authorization: Token …`; the client
follows redirects only within the same host and never from https to http.
Task IDs are checked (16 hex characters) before they reach a request path.
