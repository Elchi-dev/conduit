# Zendesk

Zendesk Support through its REST API v2: views and the tickets in them,
search, one ticket with its conversation, internal notes, public replies to
the requester, status changes and assignment.

**Setup.** Enter your `subdomain` (`acme` for `acme.zendesk.com`; the full
address works too). Then either an agent's `email` with an API token (Admin
Center, Apps and integrations, Zendesk API), or an OAuth access token in
`oauthToken`, stored in the vault. One instance is one Zendesk account.

| Action | Risk | Notes |
| --- | --- | --- |
| `views` | read | The active views with their id and title. |
| `tickets` | read, sensitive | Tickets in a `view`, or all unsolved tickets without one, most recently updated first (`limit` up to 100, 25 by default): number, subject, status, priority, assignee id and a link. |
| `search` | read, sensitive | Tickets matching a `query` in Zendesk's search syntax (`status:open requester:jane@example.com printer`), up to 500 characters on one line. |
| `ticket` | read, sensitive | One `ticket` with requester (name and email), assignee, tags, channel and its latest `comments` (up to 100, 20 by default), public and internal, oldest first. |
| `agents` | read | Agents and admins with id, name and role (no emails), to assign tickets to. |
| `add_note` | write, sensitive | An internal note on a ticket; the requester isn't notified. Zendesk can't delete comments, so it has no undo. The preview shows the text. |
| `reply` | destructive, sensitive | A public comment, which Zendesk emails to the requester and CCs. It can't be unsent. The preview shows the ticket, who gets it and the text. |
| `set_status` | write | `open`, `pending` or `hold` (also reopens a solved ticket). Solving is `resolve`. Undo sets the status it had (a new ticket goes back to open, since nothing can be set to new; a solved one is solved again with `resolve`). Closed tickets can't be changed, so closing isn't offered. |
| `resolve` | destructive | Sets a ticket `solved`. Zendesk's default triggers email the requester then (a resolution notice, a satisfaction survey), which can't be unsent; the preview says so. Undo reopens it with the status it had (`set_status`), until Zendesk closes it. |
| `assign` | write | To an agent (`assignee`, an id from `agents`) or `unassign`. The preview shows who has it now and who will; undo gives it back. |

**Why the risks.** A public reply reaches a person outside your team and
can't be taken back, so it's destructive and always needs approval under the
default policy. Solving a ticket can email the requester too (triggers send
resolution notices and satisfaction surveys), so `resolve` is destructive
as well. Notes, the other statuses and assignment stay inside the helpdesk,
and status and assignment can be undone.

**Sensitive data.** Ticket subjects, requesters and comments are customer
data, so `tickets`, `search`, `ticket`, `reply` and `add_note` (a note often
quotes the customer) are sensitive: their input and output stay out of the
audit log, approvals (except for whoever decides them) and events. The
other actions' previews, results and undo tokens are logged as they are, so
they name tickets by number and agents by name only, never a subject or the
requester.

**Security.** The API token goes as Basic auth (`email/token:…`), an OAuth
token as a Bearer token; both stay in the vault. The subdomain must be a
plain DNS label, so requests only ever go to `<subdomain>.zendesk.com`, and
the client follows redirects only within the same host and never from https
to http. Ticket, view and agent ids are numbers, statuses come from a fixed
list and texts are checked (up to 20,000 characters, no control characters)
before they reach a request.
Replies and notes go in the comment's plain-text `body` (never
`html_body`), so the customer sees the text exactly as written; markup in
it isn't rendered.
