# Zabbix

Current problems, hosts and maintenance periods, acknowledging and closing
problems, and creating or deleting maintenance, through the Zabbix API with
an API token. Works with Zabbix 5.4 and later, including 6.0 LTS and 7.x.

**Setup.** In the Zabbix frontend, open Users, API tokens (or your user
settings, API tokens), create a token and store it in the vault. Enter the
frontend's address, such as `https://zabbix.example.com` or
`https://example.com/zabbix`. The token acts with its user's role and host
permissions: acknowledging needs "Acknowledge problems", closing needs
"Close problems", and maintenance needs a role with write access to the
hosts. For a self-signed certificate, set `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `problems` | read | Current problems, newest first: event id, name, severity, hosts, since when, acknowledged and suppressed. Filter by `minSeverity`, `acknowledged` or `hosts` (host ids), up to `limit`. |
| `hosts` | read | Id, technical and visible name, whether it's monitored or in maintenance, groups, and interfaces with type, address, port and availability. `query` matches part of the name. |
| `maintenances` | read | Id, name, description, the active window, whether data is collected, and the hosts and groups covered. |
| `acknowledge` | destructive | Acknowledges up to 100 problems by event id, optionally with a `message`. The preview lists the ones that change; undo unacknowledges those (the message stays in the history). It is destructive because escalation steps that wait for an acknowledgement stop. |
| `unacknowledge` | write | Takes the acknowledgement off problems. Undo acknowledges them again. |
| `close_problems` | destructive | Closes problems by hand, optionally with a `message`. Their triggers must allow manual close. With a preview; no undo. |
| `create_maintenance` | destructive | Puts `hosts` and/or `groups` into maintenance for `minutes` (5 to 43200) from now, with or without data collection (`collectData`, default on), which suppresses their problems and notifications. The preview names the hosts and groups and the window. Undo deletes it. |
| `delete_maintenance` | destructive | Deletes a maintenance period by id, so its hosts alert normally again. With a preview showing what it covered. |

**Notes.** Problems that are already resolved, acknowledged or
unacknowledged are left as they are and reported as nothing to change.
Maintenance names are unique in Zabbix; a taken name is refused.

**Security.** The module reads the version first (that call needs no
token) and sends the token the way the server expects: in an
`Authorization: Bearer` header from 6.4 on, in the request's `auth` field
before. The client won't follow a redirect to another host or from https to
http. Ids must be numeric and names one line before anything is sent.
Host inventory and the users behind acknowledgements are never read, and
Zabbix's error text passes through the redaction filter.
