# Fastmail

Your Fastmail mailbox over JMAP: mailboxes with their counts, the newest or
matching mail, reading messages and sending.

**Setup.** In Fastmail, open Settings, Privacy & Security, Manage API
tokens, and create a token with **Email** access (read-only is enough to
read; add **Email submission** to send). Store it in the vault. Optionally
set `from` to one of your sending identities; otherwise the first one is
used. A wildcard identity (`*@example.com`) lets `from` be any address at
that domain.

| Action | Risk | Notes |
| --- | --- | --- |
| `mailboxes` | read | Every mailbox with its role (inbox, sent, …), parent, message and unread counts. |
| `mail_list` | read | Newest messages in a mailbox (a role such as `inbox` or a mailbox id), optionally only unread or matching `text`: sender, subject, preview, received, unread, attachments. Sensitive. |
| `mail_read` | read | Sender, recipients, subject, date, the text (HTML reduced to text, never rendered) and attachment names. Doesn't mark it read. Sensitive. |
| `send_mail` | destructive | A plain-text message to `to`, `cc` and `bcc` (50 recipients at most), sent from your identity and filed in Sent. The preview shows recipients, subject and body. Sensitive. |

**How sending works.** The module builds the message as MIME, uploads it,
imports it into Drafts and submits it in one JMAP request; on success
Fastmail moves it to Sent. Bcc recipients go in the submission's envelope
only, so they never appear in the message's headers.

**Security.** The token is only accepted as a `secret://` reference and
goes in the `Authorization` header. The JMAP session's API and upload
addresses must be on the same host as the session itself, and the client
won't follow a redirect to another host or from https to http, so the
token can't be sent elsewhere. Ids are checked before any request.
Subjects and addresses with line breaks are refused, so nothing can add a
header, and errors name only the JMAP error type.

## Notes

- Token access to grant: Email (to read), plus Email submission (to send).
- Mail is sent as plain text without attachments.
- The module works with Fastmail's JMAP server at `api.fastmail.com`.
