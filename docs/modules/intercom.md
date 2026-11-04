# Intercom

Intercom's inbox through its REST API: conversations and their messages,
replies to customers, internal notes, closing, snoozing and reopening, and
contact search.

**Setup.** In the Developer Hub, create an app (or open an existing one) and
copy its access token from Authentication; store it in the vault. Pick the
`region` your workspace is hosted in: `us` (default), `eu` or `au`. The token
acts as the admin who made the app, so replies and notes are posted as that
admin.

| Action | Risk | Notes |
| --- | --- | --- |
| `conversations` | read, sensitive | Conversations by `state` (`open` by default, `closed`, `snoozed` or `all`), most recently updated first (`limit` up to 50): id, title, state, priority, assignee id, customer (name, email), last update and the opening message. |
| `conversation` | read, sensitive | One `conversation` with customer, state, channel and its latest 50 parts: the customer's messages, replies, internal notes and events. |
| `contacts` | read, sensitive | Users and leads whose name or email contains `query`: id, name, email, phone, role and last seen. |
| `add_note` | write, sensitive | An internal note only teammates see; the customer isn't sent anything. The preview names the teammates it mentions. |
| `reply` | destructive, sensitive | A public reply as the token's admin, delivered in Messenger or by email. The preview shows the customer and the text, and says when the reply also reopens the conversation. |
| `open` | write | Reopens a closed or snoozed conversation. Undo closes it again, or snoozes it to the same time. |
| `snooze` | write | Snoozes a conversation `until` a future time (up to a year); Intercom reopens it then. Undo sets the state it had. |
| `close` | destructive | Closes a conversation. Intercom may ask the customer to rate it, and the preview says so. Undo sets the state it had. |

**Why the risks.** A reply reaches someone outside your team and can't be
taken back, so it's destructive. Closing can send the customer a rating
request, so `close` is destructive too. Notes, snoozing and reopening stay
inside Intercom; the state changes can be undone.

**Sensitive data.** Conversations and contacts carry customers' names,
emails and messages, so `conversations`, `conversation`, `contacts`, `reply`
and `add_note` are sensitive: their input and output stay out of the audit
log, approvals (except for whoever decides them) and events. The state
changes' previews, results and undo tokens hold the conversation id and
states only.

**Security.** The token goes in the `Authorization` header, and the client
follows redirects only within the same host and never from https to http.
Conversation ids are numbers, states come from fixed lists, texts are
checked (up to 20,000 characters, no control characters) and notes with a
wildcard mention such as `@all` are refused, all before a request is made.
Intercom bodies are HTML, so the text is sent HTML-escaped (line breaks
kept): an agent's markup (a link, an image, hidden text) reaches the
customer as the literal text the preview showed.

**Notes.** Intercom's API can't delete conversation parts, so a note has no
undo. Snoozed conversations whose wake-up time has passed undo to open.
