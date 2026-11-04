# Freshdesk

Freshdesk through its REST API v2: ticket lists and search, one ticket with
its conversation, private notes, public replies to the requester, status
changes and assignment.

**Setup.** Enter your `domain` (`acme` for `acme.freshdesk.com`; the full
address works too) and an agent's API key (Profile settings, View API key),
stored in the vault. The module acts as that agent.

| Action | Risk | Notes |
| --- | --- | --- |
| `tickets` | read, sensitive | Tickets by `filter`: `unresolved` (open or pending, the default), `new_and_my_open`, `watching` or `recent`, most recently updated first (`limit` up to 100): number, subject, status, priority, assignee id and a link. |
| `search` | read, sensitive | Tickets matching a `query` in Freshdesk's query language (`priority:4 AND status:2`, `tag:'billing'`), up to 500 characters on one line, without double quotes. |
| `ticket` | read, sensitive | One `ticket` with requester (name and email), assignee, tags, description and its latest `conversations` (up to 100, 20 by default): customer messages, replies and notes. |
| `agents` | read | Agents with id and name (no emails), to assign tickets to. |
| `add_note` | write | A private note; the requester isn't notified. Undo deletes it. The preview shows the text. |
| `delete_note` | destructive | Deletes one private `note` for good. It looks the entry up first and refuses anything that isn't a private note, so it can't remove a reply or a customer message. |
| `reply` | destructive, sensitive | A public reply, emailed to the requester. It can't be unsent. The preview shows the ticket, who gets it and the text. |
| `set_status` | write | `open`, `pending`, `resolved` or `closed`. Undo sets the status it had (when that was one of these four, not a custom status). Your automations may email the requester on a change. |
| `assign` | write | To an agent (`assignee`, an id from `agents`) or `unassign`. The preview shows who has it now and who will; undo gives it back. |

**Why the risks.** A public reply reaches a person outside your team and
can't be taken back, so it's destructive. Notes, status and assignment stay
inside the helpdesk and can be undone. Deleting a note loses it, so it's
destructive (it's what a note's undo calls, which is then approved like any
destructive action).

**Sensitive data.** Ticket subjects, requesters and conversations are
customer data, so `tickets`, `search`, `ticket` and `reply` are sensitive:
their input and output stay out of the audit log, approvals (except for
whoever decides them) and events. Private notes are the agent's own words and
are logged.

**Security.** The API key goes as Basic auth (`key:X`) and stays in the
vault. The domain must be a plain DNS label, so requests only go to
`<domain>.freshdesk.com`, and the client follows redirects only within the
same host and never from https to http. Texts are sent as escaped HTML (line
breaks kept), so nothing in them is read as markup. Ticket, note and agent
ids are numbers, filters and statuses come from fixed lists and texts are
checked (up to 20,000 characters, no control characters) before they reach a
request.
