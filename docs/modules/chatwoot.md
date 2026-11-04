# Chatwoot

Chatwoot (app.chatwoot.com or self-hosted) through its application API:
conversations, their messages, private notes, replies to the contact,
resolving and reopening, and assignment.

**Setup.** Leave the `address` at `https://app.chatwoot.com` or enter your
server. Enter the `accountId` (the number in `/app/accounts/<number>/`) and
your access token (Profile settings, Access token), stored in the vault. The
module acts as that user; one instance is one account.

| Action | Risk | Notes |
| --- | --- | --- |
| `conversations` | read, sensitive | Conversations by `status` (`open` by default, `pending`, `resolved`, `snoozed` or `all`) and `assignee` (`me`, `unassigned`, `assigned` or `all`), most recent first (`limit` up to 100): number, contact (name, email, phone), inbox, assignee, unread count, last activity and the last message. |
| `messages` | read, sensitive | One `conversation` with contact, status, assignee, channel and its latest messages, private notes included. |
| `agents` | read | Agents with id, name, role and availability (no emails), to assign conversations to. |
| `add_note` | write, sensitive | A private note only agents see; the contact isn't sent anything. Undo deletes it (the undo holds only the conversation and note numbers, so the log keeps it). |
| `delete_note` | destructive, sensitive | Deletes one private `note`; the preview quotes it. It looks the message up first and refuses anything that isn't a private note. |
| `reply` | destructive, sensitive | Sends a message to the contact on the conversation's channel (email, website chat, WhatsApp, ...). It can't be unsent. The preview shows the contact, the channel and the text. |
| `set_status` | write | `open` or `pending` (also reopens a resolved conversation). Resolving is `resolve`. Undo sets the status it had (a resolved one is resolved again with `resolve`; none after a snoozed one, which needs a wake-up time). |
| `resolve` | destructive | Resolves a conversation. Chatwoot then sends the contact the inbox's satisfaction survey or resolution message when those are on, which can't be unsent; the preview says so. Undo sets the status it had. |
| `assign` | write | To an agent (`assignee`, an id from `agents`) or `unassign`. Undo gives it back to whoever had it. |

**Why the risks.** A reply reaches a person outside your team and can't be
taken back, so it's destructive. Resolving can message the contact too (a
satisfaction survey), so `resolve` is destructive as well. Notes, the other
statuses and assignment stay inside Chatwoot and can be undone.

**Sensitive data.** Conversations carry contacts' names, emails, phone
numbers and messages, so `conversations`, `messages`, `reply`, `add_note`
and `delete_note` (notes often quote the contact) are sensitive: their input
and output stay out of the audit log, approvals (except for whoever decides
them) and events. The other actions' previews, results and undo tokens are
logged as they are, so they name conversations by number and agents by name
only, never the contact.

**Security.** The token goes in Chatwoot's `api_access_token` header. Go
forwards custom headers on redirects, so the client follows redirects only
within the same host and never from https to http. The address must be a
plain http(s) URL without credentials, query or `..`. Conversation, message,
account and agent ids are numbers, statuses come from fixed lists and texts
are checked (up to 20,000 characters, no control characters) before they
reach a request.
