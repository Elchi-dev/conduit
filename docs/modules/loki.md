# Loki

LogQL log and metric queries over a bounded time range, and label names and
values, from Grafana Loki (self-hosted or Grafana Cloud).

**Setup.** Enter Loki's address, such as `http://loki:3100`. A single-tenant
Loki asks for no credentials. For a multi-tenant one, enter the `tenant`
(sent as `X-Scope-OrgID`). For Grafana Cloud, enter the Loki user id as
`username` and store an access policy token with `logs:read` as the
password. A bearer token works too, for a proxy in front. For a self-signed
certificate, set `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `query` | read, sensitive | One LogQL query over the last `sinceMinutes` (1 to 10080, default 60). A log query returns up to `limit` lines (1 to 1000, default 100), newest first (`direction: forward` for oldest first), each with its time and labels. A metric query returns its series as time and value pairs. |
| `labels` | read | Label names seen in the range. |
| `label_values` | read | One label's values seen in the range, at most 1000. |

Queries are bounded on every side: the range is at most 7 days, a metric
query has at most 1000 steps (the step defaults to the range in 250 steps,
and a smaller `stepSeconds` that would exceed 1000 is refused before the
request), it returns at most 100 series, and a query stops after 20 seconds.
Each log line is cut at 2000 characters and an answer carries at most
256 KB of lines; `truncated` says when something was left out.

**Security.** Logs often hold passwords, tokens and personal data, so
`query` is sensitive: its input and results never go to the audit log,
approvals or events. Credentials go in the `Authorization` header, and the
client won't follow a redirect to another host or from https to http.
Label names are checked before they reach a request path, and a query must
be printable text of at most 4000 characters.

**Notes.** LogQL only reads, so there is nothing for Conduit to refuse in a
query beyond its size; Loki parses it and refuses one that selects no
stream. Loki's own limits (`max_entries_limit_per_query`,
`max_query_length`) can be lower than Conduit's and win.
