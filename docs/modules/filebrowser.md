# File Browser

Folder listings, search and disk usage on a File Browser server, and
creating and deleting share links.

**Setup.** Enter your File Browser's address, such as
`https://files.example.com` (or one under a path, like
`https://example.com/files`), the user name to sign in with, and a
`secret://` reference to that user's password in the vault. Conduit signs
in and reuses the session token for an hour, signing in again when the
server refuses it. The user's own scope and permissions apply; an admin
sees every user's share links. For a self-signed certificate, set
`fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `list` | read, sensitive | Files and folders in a folder: name, path, type, size, modified, and counts. `limit` caps the rows (default 500). File contents are never read. |
| `search` | read, sensitive | Files and folders whose name matches `query`, under `path`. |
| `usage` | read | Used and total space of the disk behind a folder, with the percentage. |
| `shares` | read, sensitive | Share links: link, path, expiry, whether it has a password, and the `id` to delete it with. Passwords and download tokens are never returned. |
| `create_share` | destructive, sensitive | A link to a file or folder that anyone who has it can open, with an optional `password` and `expireHours`. If the item already has an open link and no password or expiry is asked, that one is returned. Undo deletes the new link. |
| `delete_share` | destructive, sensitive | Deletes a link by its `id`; people with it can't open it any more. The preview names the path. |

**Link ids.** A share's hash is what opens the link, so Conduit names each
link by an id made from a one-way hash of it instead. That id is what
`delete_share` takes and what the undo holds, so the audit log never keeps
a working link.

**Security.** The password is sent only to File Browser's sign-in, and the
session token goes in the `X-Auth` header; the client won't follow a
redirect to another host or from https to http. Paths must start with `/`
with no `..` parts or control characters before any request is made, and
each part is escaped in the request path.

## Notes

- Only password sign-in is supported; a server set to proxy or no
  authentication isn't.
- Search matches names, not file contents.
