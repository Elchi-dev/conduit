# Speedtest Tracker

A [Speedtest Tracker](https://github.com/alexjustesen/speedtest-tracker)
server through its API v1 (Speedtest Tracker 1.0 and later): the latest
result, history, statistics, and queueing a speedtest.

**Setup.** In Speedtest Tracker open API Tokens, create a token with *Read
results* (and *Run speedtest* for `run`), and store it in the vault. Enter
the address, such as `http://speedtest.local:8080`.

| Action | Risk | Notes |
| --- | --- | --- |
| `latest` | read | The most recent speedtest: download and upload in Mbit/s, ping and jitter in ms, packet loss, server, ISP, healthy (against your thresholds), status, scheduled, and the speedtest.net result link. |
| `history` | read | Speedtests from the last `days` (default 7, up to 365), newest first, up to `limit` (default 50, at most 500); `more` says whether there were more. Failed tests carry their error. |
| `stats` | read | Over the last `days`: tests, completed, failed, unhealthy, and minimum, average, maximum and 10th percentile download and upload (90th percentile for ping). Computed from the newest 2,000 results at most. |
| `run` | write | Queues a speedtest now, optionally against an Ookla `serverId`. It fills the connection for about half a minute, so it's a write even though nothing is changed; there's nothing to undo. The result shows in `latest` when it finishes. |

Health is `degraded` when the latest test failed or was below your
thresholds.

**Security.** The token goes in the `Authorization: Bearer` header; the
client won't follow a redirect to another host or from https to http.
Results are read without Ookla's network interface details (internal and
external IP, MAC address) and the test server's IP. `serverId` must be a
positive number.
