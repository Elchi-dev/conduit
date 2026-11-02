# Metrics

Prometheus (or a compatible API: Mimir, Thanos, VictoriaMetrics) and Grafana.

| Setting | Meaning |
| --- | --- |
| Prometheus URL | e.g. `http://prometheus:9090` |
| Bearer token, or basic-auth user and password | if your Prometheus is protected (vault references) |
| Grafana URL | e.g. `https://grafana.example.com` |
| Grafana token | a service account token; Viewer is enough |

| Action | Risk | Notes |
| --- | --- | --- |
| `alerts` | read | Firing and pending alerts with severity and summary |
| `targets` | read | Scrape targets, optionally only those down |
| `query` | read | PromQL instant query as a table, largest first |
| `chart` | read | PromQL over the last N hours (up to 7 days), drawn as a line chart (up to 8 series) with a table view |
| `dashboards` | read | Grafana dashboards with links |

Health turns amber while any alert is firing. Dashboards open in Grafana;
embedding panels inside Conduit needs Grafana's `allow_embedding` and is
planned.
