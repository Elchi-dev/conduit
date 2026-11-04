# 1Password Connect

1Password through a [Connect server](https://developer.1password.com/docs/connect/)
you run: the server's health, the vaults its token can read, item titles,
categories, tags and field labels, and the values of named fields only
through `reveal_field`. The module never creates, edits or deletes items,
and never touches access: Connect tokens and their vault grants are managed
in 1Password itself.

**Setup.** Deploy a Connect server (its `1password-credentials.json` stays
with the server) and create a Connect token in 1Password, granting it
**read** on only the vaults Conduit should see. Enter the server's URL, such
as `http://localhost:8080`, and store the token in Conduit's vault. For a
self-signed certificate, enter its SHA-256 `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `health` | read | The Connect server's name, version and the state of its sync and database dependencies. |
| `vaults` | read | Name, id, description, type, item count and dates of each vault the token can read. |
| `items` | read | Items of a `vault` (name or id), optionally only those with exactly a `title`: id, title, category, tags, favorite, version, state, dates, and the hosts of their URLs (a URL's path, query and user info can carry a token, so only the host is shown, and only when it's a host name with a dot or an IPv4 address: an `otpauth://` link, a single word or anything else typed into a URL field is left out). Never field values. |
| `item` | read | One item (title or id): its sections and each field's label, id, type, purpose and section, whether a field is empty, and its files' names and sizes. Never values. |
| `reveal_field` | destructive, sensitive | The values of the `fields` named (labels or field ids, 1 to 10) of one item, and no others, with the ones that aren't there listed as `missing`. A label that more than one field has is refused with the fields' ids to choose from; a title that more than one item has, with the items' ids. Revealing a credential can't be taken back, so it's destructive, like Conduit's own `vault.reveal`. |

**Security.** The token is sent as `Authorization: Bearer` to the configured
server only; the client follows redirects only within the same host and
never from https to http. Vault names, item titles and field labels are
checked (no quotes, backslashes or control characters) before they go into
Connect's `title eq "…"` filter, and ids must be 26-character 1Password ids,
so nothing a caller passes can widen a query or change the request path.
