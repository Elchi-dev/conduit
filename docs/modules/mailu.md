# Mailu

Domains, users and their quota use, and aliases of a Mailu mail server, and
disabling or enabling users.

**Setup.** Turn on Mailu's API by setting `API_TOKEN` in `mailu.env` (and
restart Mailu), then store the same token in the vault. Enter the server's
address, such as `https://mail.example.com`; a path ending in `/admin` or
`/api/v1` is accepted too. For a self-signed certificate, set
`fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `domains` | read | Domain, user and alias limits (`-1` is no limit), largest mailbox allowed, sign-up, alternative names, comment, and how many managers it has. |
| `users` | read, sensitive | Address, display name, enabled, global admin, quota, storage used and percent, IMAP and POP3, and whether forwarding, auto-reply and the spam filter are on. `domain` and `enabled` filter. Personal data, so input and output stay out of the audit log, approvals and events. |
| `aliases` | read, sensitive | Address, destinations, wildcard, disabled and comment. `domain` filters. |
| `disable_user` | destructive | By `email`. Stops the user signing in to webmail, the admin interface, IMAP and POP3, and sending mail; the mailbox and its mail stay. Undo enables it. |
| `enable_user` | destructive | Lets a disabled user sign in again (it grants access, hence destructive). Undo disables it. |

Both user changes preview the user, answer "nothing to change" when it's
already as asked, and read the user back afterwards to confirm. Global
administrators, role accounts (`postmaster@`, `abuse@`, `admin@`,
`administrator@`, `root@`, `hostmaster@`, `webmaster@`, also with a `+tag`)
and users an alias of a role account delivers to are refused unless
`allowAdminAccounts` is on. If Mailu's answer doesn't say whether the user
is enabled or a global administrator, or the aliases can't be read, nothing
is changed.

**Security.** The token goes in the `Authorization` header, and the client
won't follow a redirect to another host or from https to http. Addresses and
domains are checked before they reach a request path. Users are decoded
field by field, so password hashes, forward destinations and auto-reply
text are never read; domains are too, so DNS and DKIM records aren't
either. Server messages are redacted before they're shortened.

## Notes

- The API is expected at `/api/v1`, Mailu's default (`WEB_API=/api`).
- Mailu's API token has full access to everything the API covers; keep it
  to this one use.
- Deleting users, aliases or domains and changing passwords aren't offered.
