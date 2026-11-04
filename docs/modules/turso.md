# Turso

A Turso organization through the Platform API: databases, groups,
locations, usage, and creating or deleting databases.

**Setup.** Mint a platform API token (`turso auth api-tokens mint conduit`,
or Settings, API tokens in the dashboard), store it in the vault and enter
its `secret://` reference. Set `organization` to the organization's slug
(`turso org list`); a personal account's slug is your user name.

| Action | Risk | Notes |
| --- | --- | --- |
| `databases` | read | Every database (or one `group`'s): name, id, host, group, primary location and all locations, version, whether reads or writes are blocked, sleeping and delete protection. |
| `groups` | read | Groups with their primary location, locations, version, archived, delete protection and how many databases each holds. |
| `locations` | read | The location codes Turso offers with their names. |
| `usage` | read | Rows read and written, storage and bytes synced this period, with database, location and group counts, and the same per database (by name), largest first. With `database`, that database alone. |
| `create_database` | write | Creates an empty database `name` in `group` (default `default`). The preview names the group's locations. If the database exists, nothing changes. Undo deletes it, which is destructive and asks again. |
| `delete_database` | destructive | Deletes a `database` with its data and replicas. The preview names its group and locations. A database with delete protection is refused. |

**Security.** Database auth tokens are never created or returned, and
answers are decoded field by field. The token goes in the `Authorization`
header and the client won't follow a redirect to another host. Organization,
group and database names are checked before they reach a request path.

**Notes.** To connect an app to a new database, create its token with the
Turso CLI. The health check reports databases with reads or writes blocked
(usually a plan limit) as degraded.

**Presets.** developer.
