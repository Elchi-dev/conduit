# Websites and APIs

Uptime checks for sites and APIs, and outgoing HTTP requests.

Checks are a list of `{name, url, status, contains}`: a check fails on a
connection error, a status other than `status` (or 400+ when unset), or a
body without `contains`. They run every `intervalSeconds` (default 60), and
certificate expiry is tracked for HTTPS.

| Event | When |
| --- | --- |
| `web.down` | a check starts failing |
| `web.up` | it recovers |
| `web.cert_expiring` | a certificate enters the warning window (default 14 days) |

| Action | Risk | Notes |
| --- | --- | --- |
| `status` | read | Latest result per check: up, status, latency, certificate days left |
| `check_now` | read | Runs every check immediately |
| `request` | write | Any HTTP request from this machine; response capped at 1 MiB |

`request` is a write: it can reach anything this machine can, including your
local network, so agents ask first by default.
