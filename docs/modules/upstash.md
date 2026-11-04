# Upstash

Upstash Redis databases through the Developer API: plan, regions and
state, and each database's usage this month.

**Setup.** In the Upstash console open Account, Management API, create an
API key (a read-only key is enough), store it in the vault and enter its
`secret://` reference with the account's `email`.

| Action | Risk | Notes |
| --- | --- | --- |
| `redis_databases` | read | Every Redis database: id, name, plan, primary and read regions, state, endpoint host and port, TLS, eviction, monthly budget and creation. |
| `redis_stats` | read | One `database`'s keys, storage, current connections, requests this month (reads and writes), bandwidth and cost this month, and requests per day. |

**Security.** Upstash includes each database's password and REST tokens in
its answers; the module decodes a fixed list of fields, so passwords, REST
tokens and connection strings are never read or returned. The key goes in
the `Authorization` header and the client won't follow a redirect to another
host. Database ids must be UUIDs before they reach a request path.

**Notes.** Only reading is offered. Upstash Kafka has been retired, and
QStash is managed with its own token, so neither is covered here.

**Presets.** developer.
