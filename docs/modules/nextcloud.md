# Nextcloud

Your Nextcloud: version, free space, files and who was active, your
notifications, how much you store, and file links to share.

**Setup.** The address, your user name and an **app password** (Personal
settings, Security, Devices & sessions, Create new app password), stored in
the vault. Server information needs an admin account; everything else
works with any account.

| Action | Risk | Notes |
| --- | --- | --- |
| `server` | read | Version, free space, users, files, active users in the last 5 minutes, hour and day (admin) |
| `notifications` | read | |
| `usage` | read | Used space and quota of you or another user (others need admin) |
| `share` | destructive (sensitive) | A read-only public link to a file or folder, optionally with a password and an expiry date. Undo removes the link. The link is kept out of the audit log. Destructive, because a public link changes who can see the file |
| `unshare` | write | Removes a share by its id |

An app password can be revoked on its own in Nextcloud without changing
your real password; use one for Conduit and nothing else.
