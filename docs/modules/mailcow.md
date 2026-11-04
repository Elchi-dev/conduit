# mailcow

Domains, mailboxes and their quota use, aliases, the quarantine and the mail
queue of a mailcow: dockerized server, flushing the queue, and disabling or
enabling mailboxes.

**Setup.** In mailcow's admin interface, open System, Configuration, Access,
expand API, and create a key: read-only is enough for the listings, while
flushing the queue and disabling or enabling mailboxes need read-write. Add
Conduit's IP address to the key's allowed addresses, store the key in the
vault, and enter the server's address, such as `https://mail.example.com`.
For a self-signed certificate, set `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `status` | read | The mailcow version, and each container's state, image and start time, with how many are running. |
| `domains` | read | Domain, active, mailbox and alias counts with their limits, storage used and allowed, largest mailbox allowed, message count and stored bytes, backup MX and relay-all-recipients. |
| `mailboxes` | read, sensitive | Address, name, domain, active and state, quota, storage used and percent, and message count. `domain` and `active` filter. Personal data, so input and output stay out of the audit log, approvals and events. |
| `aliases` | read, sensitive | Address, destinations, domain, active and catch-all. `domain` filters. |
| `quarantine` | read, sensitive | How many messages are held and how many for a virus, counts by sender and recipient domain, and up to 100 items with id, time, spam score and the two domains. |
| `queue` | read, sensitive | How many messages wait, by Postfix queue (`deferred`, `active`, `hold` …), their total size and the oldest, and counts by sender and recipient domain. |
| `flush_queue` | write | Asks Postfix to try delivering queued mail now (`postqueue -f`); reports the queue size before and after. With nothing waiting outside `hold`, nothing is sent. |
| `disable_mailbox` | destructive | By `mailbox` address. Sets the mailbox inactive: it can't sign in and mailcow stops accepting its mail; stored mail stays. Undo enables it. |
| `enable_mailbox` | destructive | Sets the mailbox active again (it grants access, hence destructive). Undo disables it. |

Both mailbox changes preview the mailbox and its state, answer "nothing to
change" when it's already as asked, and read the mailbox back afterwards to
confirm. Role accounts (`postmaster@`, `abuse@`, `admin@`, `administrator@`,
`root@`, `hostmaster@`, `webmaster@`) are refused unless
`allowAdminAccounts` is on.

**Security.** The key goes in the `X-API-Key` header, and the client won't
follow a redirect to another host or from https to http. Addresses and
domains are checked before they reach a request path. Mailboxes, the
quarantine and the queue are decoded field by field: password hashes,
two-factor secrets, sender permissions, subjects, message content, queue ids
and full sender or recipient addresses of quarantined and queued mail are
never read or passed on. Server messages are redacted before they're
shortened.

## Notes

- Flushing is the only queue change offered: it delivers nothing that
  wasn't already on its way, and deletes nothing. Deleting the queue,
  releasing or deleting quarantined items, and deleting anything else
  aren't offered.
- A mailbox in mailcow's "sign-in disallowed" state (`active` 2) shows as
  such; disabling it and undoing that leaves it fully active.
- mailcow's administrator and domain-administrator logins are separate from
  mailboxes and aren't listed or changed.
