# NocoDB

Bases, tables and fields of NocoDB (NocoDB Cloud or self-hosted), and
listing, creating, updating and deleting records.

**Setup.** Open Account settings, Tokens, create an API token and store it
in the vault. Leave the address as `https://app.nocodb.com` for NocoDB
Cloud, or enter your server's address, such as
`https://nocodb.example.com`. The token acts with its user's roles. For a
self-signed certificate, set `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `bases` | read | Id and title. |
| `tables` | read | A base's tables: id (used as `table`), title, and whether it's a view of an external database. |
| `fields` | read | A table's fields: title, type, primary key, required, and whether NocoDB fills it in. |
| `list_records` | read, sensitive | Records with conditions (`where`), a sort (`-Due date`), and pages of up to 100, with the total. |
| `create_record` | write, sensitive | Adds a record, fields by title. Undo deletes it. |
| `update_record` | write, sensitive | Sets the given fields only. The preview shows each changed field before and after; when every value already matches, nothing is sent. |
| `delete_record` | destructive | Deletes a record; the preview names it by key only. |

**Filters.** `where` is a list of conditions that must all hold, each a
`field` (its title), an `op` (`eq`, `ne`, `gt`, `gte`, `lt`, `lte`,
`contains`, `empty`, `notempty`) and a `value`. Conduit checks the field
against the table and writes NocoDB's where expression itself.

**Security.** Records are sensitive: their content stays out of the audit
log, approvals and events. User fields (User, Created by, Last modified by)
come back as display names, never e-mail addresses, and can't be filtered
on or set; so do users a lookup, rollup or formula shows, and lookups can't
be filtered on or sorted by (a condition on one could find e-mails a guess
at a time). The token goes in the `xc-token` header and the client won't
follow a redirect to another host or from https to http. Table ids and
record keys must be plain identifiers before any request is made.

**Notes.** NocoDB's where syntax has no quoting, so field titles and values
in conditions can't contain `(`, `)`, `,`, `~` or a backslash. Formula, lookup, rollup,
link, attachment and automatic fields can't be set here. An update has no
undo: it would need the previous values in the undo record, which the
audit log doesn't keep for sensitive actions.
