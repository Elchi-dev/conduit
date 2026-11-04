# Directus

Collections and fields of a Directus project, listing, reading, creating,
updating and deleting items, and running flows with a webhook or manual
trigger.

**Setup.** In the User Directory, choose a user for Conduit (a dedicated
one with a role that can reach the collections it needs), generate a static
token under Token, save the user and store the token in the vault. Enter
the project's address, such as `https://directus.example.com` or
`https://example.directus.app`. For a self-signed certificate, set
`fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `collections` | read | The project's own collections: name, note, singleton, hidden, folder. |
| `fields` | read | A collection's fields: name, type, interface, primary key, required, read only, hidden, and whether it's a secret field. |
| `list_items` | read, sensitive | Items with conditions (`where`), a sort (`-date_created`), and pages of up to 100, with the total. |
| `get_item` | read, sensitive | One item by primary key. |
| `create_item` | write, sensitive | Adds an item; the preview lists the fields. Undo deletes it. |
| `update_item` | write, sensitive | Sets the given fields only. The preview shows each changed field before and after; when every value already matches, nothing is sent. |
| `delete_item` | destructive | Deletes an item; the preview names it by key only. |
| `flows` | read | Id, name, status, trigger and, for webhooks and manual flows, the method. |
| `trigger_flow` | destructive, sensitive | Runs an active webhook or manual flow, with `payload` as the body of a POST webhook (or `{"collection": …, "keys": […]}` for a manual flow). Its answer is returned. |

**Filters.** `where` is a list of conditions that must all hold, each a
`field`, an `op` (`eq`, `ne`, `gt`, `gte`, `lt`, `lte`, `contains`, `empty`,
`notempty`) and a `value`. Conduit checks the field against the collection
and sends a Directus filter object, so values are never part of an
expression.

**Security.** Items are sensitive: their content stays out of the audit
log, approvals and events. System collections (`directus_users`,
`directus_sessions`, `directus_settings` and every other `directus_` one)
are never read or changed, so users' e-mails, password hashes and tokens
stay on the server. Hash, concealed and masked fields are left out of every
item and can't be filtered on, sorted by or set; filters take a collection's
own fields only, not paths through relations. Running a flow is
destructive because its operations can do anything (send mail, call APIs,
change data); flows on event, schedule or operation triggers aren't run
from here. The token goes in the `Authorization` header and the client
won't follow a redirect to another host or from https to http.

**Notes.** The token acts with its user's role, so Directus answers "not
allowed" for anything the role can't see, whether or not it exists. An
update has no undo: it would need the previous values in the undo record,
which the audit log doesn't keep for sensitive actions.
