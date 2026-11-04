# Crisp

A Crisp website's inbox through the REST API: conversations and their
messages, messages to visitors, private notes, and resolving and reopening.

**Setup.** In the Crisp Marketplace, create a plugin, ask for a production
token with the website conversation and message scopes, and install the
plugin on your website. Store the token's identifier and key in the vault
and enter both references. Enter the `websiteId` from Settings, Website
settings, Setup instructions. One instance is one website.

| Action | Risk | Notes |
| --- | --- | --- |
| `conversations` | read, sensitive | Conversations by `state` (`unresolved` by default, `resolved` or `all`), most recent first (`limit` up to 50): session id, visitor (name, email, phone), state, unread count, assignee, topic and the last message. |
| `messages` | read, sensitive | One `conversation` (its session id) with visitor and state and its latest messages: text, origin, sender and time, private notes included. |
| `send_message` | destructive, sensitive | A text message from an operator, shown in the chat and emailed by Crisp when the visitor is away. The preview shows the visitor and the text. |
| `add_note` | write, sensitive | A private note only operators see; the visitor isn't sent anything. |
| `set_state` | write | `unresolved` or `pending` (also reopens a resolved conversation). Resolving is `resolve`. Undo sets the state it had. |
| `resolve` | destructive | Resolves a conversation. Crisp may ask the visitor to rate it or email a transcript, and the preview says so. Undo sets the state it had. |

**Why the risks.** A message reaches the visitor and can't be taken back, so
`send_message` is destructive. Resolving can message the visitor too, so
`resolve` is destructive as well. Notes and the other states stay inside
Crisp; the state changes can be undone.

**Sensitive data.** Conversations carry visitors' names, emails, phone
numbers and messages, so `conversations`, `messages`, `send_message` and
`add_note` are sensitive: their input and output stay out of the audit log,
approvals (except for whoever decides them) and events. The state changes'
previews, results and undo tokens hold the session id and states only.

**Security.** The identifier and key go in the `Authorization` header with
the plugin tier, and the client follows redirects only within the same host
and never from https to http. Website and session ids must have Crisp's
exact shape, states come from fixed lists, texts are checked (up to 10,000
characters, no control characters) and notes with a wildcard mention such
as `@everyone` are refused, all before a request is made.
Messages are sent as Crisp `text` messages, which the chat box shows as
text with Crisp's light formatting, not as HTML.

**Notes.** Messages and notes have no undo. Only text messages are sent;
files and other message types show in `messages` without their content.
