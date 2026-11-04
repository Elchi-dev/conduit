# PocketBase

Collections and their fields on a PocketBase server, and listing, reading,
creating, updating and deleting records.

**Setup.** In the dashboard, open System, Superusers and create a superuser
for Conduit (a dedicated one is best); store its password in the vault.
Enter the server's address, such as `https://pb.example.com`, the
superuser's e-mail address and the password's `secret://` reference. For a
self-signed certificate, set `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `collections` | read | Name, id, type (`base`, `view`, `auth`), whether it's a system collection, and the number of fields. Auth and system collections are marked as not available for records. |
| `schema` | read | A collection's fields (name, type, required, hidden, system) and its API rules (`anyone`, `superusers only`, or the rule). |
| `list_records` | read, sensitive | Records with conditions (`where`), a sort (`-created`), and pages of up to 100. |
| `get_record` | read, sensitive | One record by id. |
| `create_record` | write, sensitive | Adds a record; the preview lists the fields. Undo deletes it. |
| `update_record` | write, sensitive | Sets the given fields only. The preview shows each changed field before and after; when every value already matches, nothing is sent. |
| `delete_record` | destructive | Deletes a record; the preview names it by id and dates, never its values. |

**Filters.** `where` is a list of conditions that must all hold, each a
`field`, an `op` (`eq`, `ne`, `gt`, `gte`, `lt`, `lte`, `contains`, `empty`,
`notempty`) and a `value` (text, a number or true/false). Conduit checks the
field against the collection and writes the PocketBase filter itself,
quoting every value, so a value is always compared as a value.

**Security.** Records can hold anything, so reads and writes of them are
sensitive: their content stays out of the audit log, approvals and events.
Records of auth collections (`users` and any other) and system collections
(`_superusers`, `_mfas`, `_otps`, `_externalAuths`, `_authOrigins`) are
never read or changed, so e-mail addresses, password hashes and token keys
stay on the server, and neither are those of a view collection whose query
reads one of them (it would show their e-mails as plain fields). Hidden fields are left out of every record and can't be
filtered on, sorted by or set. The password is only sent to sign in; the
client won't follow a redirect to another host or from https to http.
Collection names and record ids must be plain identifiers before any
request is made.

**Notes.** PocketBase 0.23 or later (it introduced `_superusers`). File
fields can't be set here, and relations aren't expanded. An update has no
undo: it would need the previous values in the undo record, which the audit
log doesn't keep for sensitive actions.
