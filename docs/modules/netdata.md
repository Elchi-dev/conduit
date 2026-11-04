# Netdata

A Netdata agent's system info, alarms, charts and their latest values, the
nodes a parent receives streams from, and silencing alarm notifications,
through the v1 and v2 APIs.

**Setup.** Enter the agent's address, such as `http://server.lan:19999`
(it defaults to `http://localhost:19999`). Most agents answer without
credentials; for one that requires a bearer token, store it in the vault
and set `token`. To list or change silencers, store the health management
API key (the contents of `/var/lib/netdata/netdata.api.key` on the agent)
in the vault and set `managementKey`. For a self-signed certificate, set
`fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `info` | read | Netdata version, OS, kernel, architecture, virtualization and container, CPU cores, memory and disk, alarm counts by status, collectors and streamed hosts. |
| `alarms` | read | Raised alarms (warning and critical), critical first, or with `all` every alarm: name, chart, status, value, since when, summary and info, and whether it's silenced or disabled. `status` filters. |
| `charts` | read | Chart id, title, units, context, family and update interval; `query` matches part of the id, title or context. |
| `metric` | read | One `chart`'s dimensions averaged over the last `seconds` (default 60), with its title and units. |
| `nodes` | read | The nodes the agent knows through the v2 API: name, id, state and version; on an agent without v2, the streamed hosts and whether they're reachable. |
| `silencers` | read | Whether all alarms are silenced, the selectors that are, and whether checks are disabled through the management API. |
| `silence` | destructive | Stops notifications for every alarm (`all`) or for the ones matching `alarm`, `chart`, `context` and `host` patterns; the checks keep running and alarms still show. Undo removes the silencing when there was none before. |
| `unsilence` | write | Removes every silencer (and any disabled checks) set through the management API. Undo puts back a previous "silence all" or a single silencer. |

**Notes.** Silencers live in the agent's memory and end when it restarts.
On a parent, `host` selects which streamed nodes a silencer covers.
Selectors are Netdata simple patterns, such as `*10min*` or
`disk_space.* !disk_space.boot`.

**Security.** The bearer token goes in the `Authorization` header and the
management key in `X-Auth-Token`, only on management requests, and the
client won't follow a redirect to another host or from https to http.
Chart ids and selectors are checked before anything is sent, and query
values are escaped. The machine GUID, host labels and alarm recipients are
never read.
