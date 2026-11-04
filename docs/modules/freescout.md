# FreeScout

A self-hosted FreeScout help desk through its API & Webhooks module:
mailboxes, conversations and their threads, replies to customers, internal
notes, and status changes.

**Setup.** Install and enable the API & Webhooks module, then open Manage,
API & Webhooks and copy the API key; store it in the vault. Enter your
server's address, such as `https://support.example.com`, and the `userId`
replies, notes and status changes are made as (Manage, Users: the number in
that user's address). For a self-signed certificate, set `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `mailboxes` | read | Id, name and address of each mailbox. |
| `conversations` | read, sensitive | Conversations by `status` (`active` by default, `pending`, `closed` or `all`), in one `mailbox` or all, most recently updated first (`limit` up to 50): id, number, subject, status, mailbox, customer (name, email), assignee, a preview and a link. |
| `conversation` | read, sensitive | One `conversation` with customer, assignee and its threads: customer emails, replies and internal notes. |
| `add_note` | write, sensitive | An internal note only your team sees; the customer isn't emailed. The preview names the users it mentions. |
| `reply` | destructive, sensitive | A reply emailed to the conversation's customer, from the configured user. The preview shows the subject, the customer and the text. |
| `set_status` | write | `active` or `pending` (also reopens a closed conversation). Closing is `close`. Undo sets the status it had. |
| `close` | destructive | Closes a conversation. FreeScout workflows may email the customer when it closes, and the preview says so. Undo sets the status it had. |

**Why the risks.** A reply reaches someone outside your team and can't be
taken back, so it's destructive. Closing can run workflows that email the
customer, so `close` is destructive as well, matching the other help-desk
modules. Notes and the other statuses stay inside FreeScout; status changes
can be undone.

**Sensitive data.** Conversations carry customers' names, emails and
messages, so `conversations`, `conversation`, `reply` and `add_note` are
sensitive: their input and output stay out of the audit log, approvals
(except for whoever decides them) and events. The status changes' previews,
results and undo tokens hold the conversation id and statuses only.

**Security.** The API key goes in FreeScout's `X-FreeScout-API-Key` header.
Go forwards custom headers on redirects, so the client follows redirects
only within the same host and never from https to http. The address must be
a plain http(s) URL without credentials, query or `..`. Conversation,
mailbox and user ids are numbers, statuses come from fixed lists, texts are
checked (up to 20,000 characters, no control characters) and notes with a
wildcard mention such as `@all` are refused, all before a request is made.

**Notes.** FreeScout's API can't delete threads, so a note has no undo.
Marking conversations as spam isn't offered. The health check reads the
configured user, so it confirms both the key and the user id.
