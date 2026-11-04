# Wazuh

Agents and their status from a Wazuh server, restarting an agent, and,
through the Wazuh indexer, an alerts summary, recent alerts and
vulnerabilities by severity.

**Setup.** Enter the server API's address, such as
`https://wazuh.example.com:55000`, and an API user (Server management,
Security, Users); store its password in the vault. A read-only role is
enough to read; restarting agents needs `agent:restart`. Wazuh makes a
self-signed certificate, so set `fingerprint` to its SHA-256 fingerprint.
For alerts and vulnerabilities, also enter the indexer's address (such as
`https://wazuh.example.com:9200`) and a user that can read `wazuh-alerts-*`
and `wazuh-states-vulnerabilities-*`, with `indexerFingerprint` for its
certificate.

| Action | Risk | Notes |
| --- | --- | --- |
| `agents` | read | Id, name, address, status, OS, agent version, groups, cluster node and last keep-alive, and counts by status. `status` filters (`active`, `disconnected`, `never_connected`, `pending`). |
| `alerts` | read | Alerts over `hours` (default 24) at or above `minLevel`, counted by rule level, with the ten most frequent rules (id, description, level) and the ten agents with the most alerts. `agent` limits it to one agent. |
| `recent_alerts` | read, sensitive | The latest alerts at or above `minLevel` (default 7): time, rule, level, groups, agent, source address, location and the log line, cut to 500 characters with credentials masked. |
| `vulnerabilities` | read | Vulnerabilities by severity, the most common CVEs and the most affected agents, for all agents or one. |
| `restart_agent` | destructive | Restarts the agent on one host. The preview names the agent, its address and OS. Only a connected agent can be restarted, and never the manager (`000`). |

**Security.** The password is exchanged for a session token, kept in memory
and renewed before Wazuh's 15-minute lifetime runs out. The server and the
indexer each have their own client, and neither follows a redirect to
another host or from https to http. Agent ids are checked as numbers before
they reach a request. Log lines can carry attacker payloads and internal
host names, so only `recent_alerts` returns them, and it's kept out of logs.

**Notes.** Alerts are kept in the indexer, not the server API, so `alerts`
and `recent_alerts` need the indexer settings. Vulnerabilities come from
the indexer on Wazuh 4.8 and later; on earlier versions, `vulnerabilities`
for one agent reads them from the server API.
