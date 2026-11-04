# Supabase

Supabase projects through the Management API: organizations, projects with
their status and region, the health of each project's services, database
size and connections, edge functions, and pausing or restoring a project.

**Setup.** In the Supabase dashboard open Account, Access tokens, generate
a personal access token with an expiry, store it in the vault and enter its
`secret://` reference. It acts with your permissions in every organization
you belong to.

| Action | Risk | Notes |
| --- | --- | --- |
| `organizations` | read | The organizations the token can see. |
| `projects` | read | Every project: reference id, name, status (and in words: running, paused, restoring…), region, organization, Postgres version and API address. |
| `health` | read | A `project`'s database, auth, REST, realtime, storage and pooler: healthy or not, status and error. |
| `database_usage` | read | Database size, connections in use out of the maximum, and the ten largest tables with their size and row estimate. It runs two fixed, read-only SQL queries through the Management API's query endpoint; nothing from the input reaches the SQL. |
| `functions` | read | Edge functions with their status, version, whether they verify JWTs, last update and address. |
| `pause` | destructive | Pauses a running project: its database, APIs and functions stop answering until restored. Supabase only pauses projects on the free plan. The preview names the project and region; undo restores it. |
| `restore` | write | Restores a paused project (a few minutes); undo pauses it again. |

**Security.** API keys, the database password and connection strings are
never requested or returned (the module doesn't call the API keys
endpoint). The token goes in the `Authorization` header and the client
won't follow a redirect to another host. Project reference ids (20
lowercase letters) are checked before they reach a request path.

**Presets.** developer.
