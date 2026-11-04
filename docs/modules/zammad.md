# Zammad

A Zammad helpdesk (self-hosted or hosted) through its REST API: open
tickets and search, one ticket with its articles, internal notes, email
replies to the customer and state changes.

**Setup.** Enter your Zammad `address` and an access token (Profile, Token
Access) with the `ticket.agent` permission, stored in the vault. For a
self-signed certificate, enter its SHA-256 `fingerprint`. The module acts as
the token's user.

| Action | Risk | Notes |
| --- | --- | --- |
| `tickets` | read, sensitive | New and open tickets (only yours with `mine`), most recently updated first (`limit` up to 100): id, number, title, state, priority, group, owner, customer and a link. Actions take the ticket's **id**, not its number. |
| `search` | read, sensitive | Tickets matching a Zammad search `query` (`printer`, `state.name:open AND priority_id:3`), up to 500 characters on one line. |
| `ticket` | read, sensitive | One `ticket` with its latest `articles` (up to 100, 20 by default): emails, notes and calls, internal ones included, with sender, type and text (HTML turned into text). |
| `add_note` | write | An internal note; the customer isn't notified. Undo deletes it, which Zammad allows an agent for their own notes for a few minutes (an admin longer). |
| `delete_note` | destructive | Deletes one internal `note`. It reads the article first and refuses anything that isn't an internal note on that ticket. |
| `reply` | destructive, sensitive | An email to the ticket's customer (their address from Zammad), with the ticket's title as subject. It can't be unsent. The preview shows the address and the text. |
| `set_state` | write | `open`, `closed`, `new`, or `pending reminder` / `pending close` with `pendingUntil` (a time, at most five years ahead). Undo sets the state it had, with its pending time. Merged and removed tickets are left alone. |

**Why the risks.** A reply reaches a person outside your team and can't be
taken back, so it's destructive. Notes and state changes stay inside the
helpdesk and can be undone.

**Sensitive data.** Tickets and articles are customer data, so `tickets`,
`search`, `ticket` and `reply` are sensitive: their input and output stay
out of the audit log, approvals (except for whoever decides them) and
events. Internal notes are the agent's own words and are logged.

**Security.** The token goes as `Authorization: Token token=…` and stays in
the vault. The client follows redirects only within the same host and never
from https to http. The address must be a plain http(s) URL without
credentials, query or `..`. Ticket and article ids are numbers, states come
from a fixed list, pending times are parsed, and texts are checked (up to
20,000 characters, no control characters) before they reach a request.
