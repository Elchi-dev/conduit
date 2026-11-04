# Strapi

Content types of a Strapi project (5, or 4), listing, reading, creating,
updating and deleting entries, and publishing and unpublishing them.

**Setup.** In the admin panel, open Settings, API Tokens and create a token:
full access, or custom with `find`, `findOne`, `create`, `update` and
`delete` on your content types and read on Content-type-builder; store it in
the vault. Enter the project's address, such as `https://cms.example.com`,
and set `version` to 4 for a Strapi 4 project. For a self-signed
certificate, set `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `content_types` | read | The project's collection types: plural API id (used as `type`), name, whether drafts are on, and their fields. |
| `list_entries` | read, sensitive | Entries with conditions (`where`), a sort (`-publishedAt`), pages of up to 100 and, on Strapi 5, `status` (`draft` or `published`). |
| `get_entry` | read, sensitive | One entry by `documentId` (Strapi 5) or id (Strapi 4). |
| `create_entry` | write, sensitive | Adds an entry, as a draft on a type with drafts. Undo deletes it. |
| `update_entry` | write, sensitive | Sets the given fields (of the draft, on Strapi 5). The preview shows each changed field before and after; when every value already matches, nothing is sent. |
| `delete_entry` | destructive | Deletes an entry; the preview names it by id only. |
| `publish_entry` | destructive | Makes the entry public (on Strapi 5, its current draft). When the published version already matches, nothing is sent. On Strapi 4, undo unpublishes it. |
| `unpublish_entry` | destructive | Takes the entry back to a draft (Strapi 4). Undo publishes it. |

**Filters.** `where` is a list of conditions that must all hold, each a
`field`, an `op` (`eq`, `ne`, `gt`, `gte`, `lt`, `lte`, `contains`, `empty`,
`notempty`) and a `value`. Conduit checks the field against the content
type and sends each condition as its own `filters[...]` parameter.

**Security.** Entries are sensitive: their content stays out of the audit
log, approvals and events. Only the project's own collection types
(`api::`) are reached, so plugin and admin types such as
`users-permissions` users, with their e-mails and password hashes, are
never read or changed. Private and password fields are left out of every
entry and can't be filtered on or set, and relations aren't populated.
Publishing and unpublishing are destructive because they change what the
public sees. The token goes in the `Authorization` header and the client
won't follow a redirect to another host or from https to http.

**Notes.** Strapi 5's REST API can't unpublish an entry, so on Strapi 5
`unpublish_entry` explains that and changes nothing, and publishing has no
undo. On Strapi 4 an entry has one version, so updating a published entry
changes it publicly. An update has no undo: it would need the previous
values in the undo record, which the audit log doesn't keep for sensitive
actions.
