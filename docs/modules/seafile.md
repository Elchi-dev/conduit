# Seafile

Libraries, folder listings and file details on a Seafile server, and
creating and revoking share links.

**Setup.** In Seafile, open Settings and copy your Web API Auth Token (or
get one from `/api2/auth-token/`); store it in the vault. Enter your
server's address, such as `https://seafile.example.com` (a server under a
path, like `https://example.com/seafile`, works too). The token acts as its
user. For a self-signed certificate, set `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `libraries` | read | Id, name, size, last change, kind (`mine`, `shared`, `group`), encrypted, and your permission. Owners' names and emails are left out. |
| `list_dir` | read, sensitive | Files and folders in a library folder: name, type, size, modified. `limit` caps the rows (default 500). |
| `file_info` | read, sensitive | A file's name, path, size, modified time and id. |
| `share_links` | read, sensitive | Your share links, or those of one library or path: link, library, path, views, created, expiry, and the `id` to revoke it with. Passwords are never returned. |
| `create_share_link` | destructive, sensitive | A view-and-download link to a file or folder that anyone who has it can open, with an optional `password` and `expireDays`. If the item already has a link and no password or expiry is asked, that one is returned. The preview says who could open it. Undo revokes the new link. |
| `revoke_share_link` | destructive, sensitive | Deletes a link by its `id`; people with it can't open it any more. The preview names the path and its views. |

**Link ids.** A share link's token is what opens it, so Conduit names each
link by an id made from a keyed hash (HMAC-SHA-256) of the token instead,
keyed with the instance and its API token, so the id can't be worked back
to the token even when tokens are short. That id is what
`revoke_share_link` takes and what the undo holds, so the audit log never
keeps a working link. Ids change when the API token does.

**Reusing links.** An existing link is returned only when it is
view-and-download (not one that lets people edit or upload). An older
Seafile that answers a new link with the item's existing one is detected:
the result says the password and expiry weren't applied, and no undo is
offered, so undoing never revokes a link that was there before.

**Security.** The token goes in the `Authorization` header, and the client
won't follow a redirect to another host or from https to http. Library ids
must be UUIDs and paths must start with `/` with no `..` parts or control
characters before any request is made; paths go only in query strings and
JSON bodies.

## Notes

- Share links on encrypted libraries aren't possible in Seafile, and
  listing an encrypted library needs it unlocked in Seafile first.
- Some servers require link passwords of a minimum length (8 by default).
