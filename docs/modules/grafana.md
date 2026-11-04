# Grafana

Dashboards, alert rules and their state, firing alerts, silences and
annotations on a Grafana server (Grafana 9 and later, Grafana-managed
alerting). The [Metrics](metrics.md) module can also list Grafana dashboards
next to Prometheus; this module covers alerting and writes.

**Setup.** In Grafana, Administration, Service accounts, add a service
account and a token for it, and store the token in the vault. The Viewer role
is enough to read; creating silences and annotations needs Editor. Enter the
server address, such as `https://grafana.example.com` (a sub-path like
`https://example.com/grafana` works too).

| Action | Risk | Notes |
| --- | --- | --- |
| `dashboards` | read | Search by `query` and `tag`, with links. |
| `alert_rules` | read | Every Grafana-managed rule with folder, group, state (firing, pending, inactive), health, last error and active alert count. `state` filters. |
| `alerts` | read | Alerts firing now, not silenced unless `includeSilenced`. |
| `silences` | read | Active and pending silences; `includeExpired` adds expired ones. |
| `create_silence` | write | `matchers` (name, value, `isRegex`, `isEqual`), `durationMinutes` (1 minute to 30 days, default 2 hours) and a required `comment`. The preview shows the silence. Undo expires it. |
| `expire_silence` | write | Ends a silence now. The preview shows it; undo creates it again with the same matchers for the time it had left. |
| `annotate` | write | An annotation on every dashboard, or on one (`dashboardUID`, optional `panelId`), at `time` (default now) or over a region to `timeEnd`. Undo deletes it. |
| `delete_annotation` | destructive | With a preview. |

**Security.** The token goes in the `Authorization` header, and the client
won't follow a redirect to another host or from https to http. Silence ids
and dashboard uids are checked before they go into a request path, regex
matchers must compile, and alert data is read only through the alerting
APIs listed above.
