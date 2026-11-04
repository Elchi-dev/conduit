# Help Scout

Help Scout's Inbox API: mailboxes, conversations and their threads, replies
to customers, internal notes, and status changes.

**Setup.** In Help Scout, open Your Profile, My Apps and create an app (any
redirect URL works). Store its app id and app secret in the vault and enter
both references. The module signs in with OAuth client credentials and acts
as the user who created the app, so give that user access to the mailboxes
you want. Tokens are kept in memory only and renewed before they expire.

| Action | Risk | Notes |
| --- | --- | --- |
| `mailboxes` | read | Id, name and address of each mailbox. |
| `conversations` | read, sensitive | Conversations by `status` (`active` by default, `pending`, `open` for both, `closed` or `all`), in one `mailbox` or all, most recently updated first (`limit` up to 50): id, number, subject, status, mailbox, customer (name, email), assignee, tags and a preview. |
| `conversation` | read, sensitive | One `conversation` with customer, assignee, tags and its threads: customer emails, replies and internal notes. |
| `add_note` | write, sensitive | An internal note only your team sees; the customer isn't emailed. The preview names the users it mentions. |
| `reply` | destructive, sensitive | A reply emailed to the conversation's customer. The preview shows the subject, the customer and the text. |
| `set_status` | write | `active` or `pending` (also reopens a closed conversation). Closing is `close`. Undo sets the status it had. |
| `close` | destructive | Closes a conversation. Help Scout workflows may email the customer when it closes, and the preview says so. Undo sets the status it had. |

**Why the risks.** A reply reaches someone outside your team and can't be
taken back, so it's destructive. Closing can run workflows that email the
customer, so `close` is destructive as well, matching the other help-desk
modules. Notes and the other statuses stay inside Help Scout; status
changes can be undone.

**Sensitive data.** Conversations carry customers' names, emails and
messages, so `conversations`, `conversation`, `reply` and `add_note` are
sensitive: their input and output stay out of the audit log, approvals
(except for whoever decides them) and events. The status changes' previews,
results and undo tokens hold the conversation id and statuses only.

**Security.** The app id and secret are sent only to Help Scout's token
endpoint, and the access token only in the `Authorization` header; the
client follows redirects only within the same host and never from https to
http. Conversation and mailbox ids are numbers, statuses come from fixed
lists, texts are checked (up to 20,000 characters, no control characters)
and notes with a wildcard mention such as `@all` are refused, all before a
request is made.
Thread bodies are HTML, so the text is sent HTML-escaped (line breaks
kept): an agent's markup (a link, an image, hidden text) reaches the
customer as the literal text the preview showed.

**Notes.** Help Scout's API can't delete threads, so a note has no undo.
Marking conversations as spam isn't offered.
