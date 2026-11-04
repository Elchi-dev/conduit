# Microsoft 365

Outlook mail, calendar, Teams and OneDrive through Microsoft Graph: list
and read mail, send it, see and add calendar events, schedule meetings,
post to a Teams channel and list OneDrive files.

**Setup.** In the Microsoft Entra admin center, open App registrations, New
registration. Copy its Directory (tenant) id and Application (client) id,
then add a client secret (Certificates & secrets) and store it in the
vault. The module signs in one of two ways:

- **As an app** (client credentials): add Graph *application* permissions
  and grant admin consent, then enter the mailbox to act on as `user`
  (`alex@contoso.com`). Good for a shared or service mailbox.
- **As a user** (delegated): add Graph *delegated* permissions, sign the
  user in once with the authorization code flow and `offline_access`, and
  store the refresh token in the vault as `refreshToken`. Leave `user`
  empty: the module acts as that user. Posting to Teams needs this mode.

| Action | Risk | Notes |
| --- | --- | --- |
| `mail_list` | read | Newest messages in `inbox`, `sentitems`, `drafts`, `archive`, `deleteditems`, `junkemail` or a folder id: sender, subject, preview, received, unread, attachments. `unreadOnly` filters. Sensitive. |
| `mail_read` | read | Sender, recipients, subject, received, the body as text (Microsoft converts HTML; nothing is rendered) and attachment names. Doesn't mark it read. Sensitive. |
| `send_mail` | destructive | A plain-text message to `to`, `cc` and `bcc` (50 recipients at most). The preview shows the recipients, subject and body. Sensitive. |
| `events` | read | Events in the next `days` (7 by default, up to 60) in UTC: subject, start, end, location, organizer, attendees with their answers. Sensitive. |
| `create_event` | write | A private event without attendees; nobody is notified. Undo deletes it. Sensitive. |
| `schedule_meeting` | destructive | An event with `attendees`, who each get an invitation; `online` adds a Teams link. The preview shows the attendees and the description they'll get. Undo deletes it, which sends a cancellation. Sensitive. |
| `delete_event` | destructive | Deletes an event; for a meeting you organize, attendees get a cancellation. The preview shows its time and attendee count, never the subject or names, and says when the id is a recurring series' master (deleting it deletes every occurrence). An event that's already gone is "nothing to change". |
| `post_channel_message` | destructive | Plain text to a channel (`team` id and `channel` id) as the signed-in user. The preview names who's mentioned. Sensitive. |
| `files` | read | Files and folders in a OneDrive folder (`path`, empty for the root): name, size, modified, type and link. Sensitive. |

Every action that returns mail, events or file names is sensitive, so the
audit log, approvals and events keep only its shape.

**Security.** Credentials are only accepted as `secret://` references.
Access tokens live in memory per instance until shortly before they
expire; a refused token is dropped and fetched again once. When Microsoft
rotates the refresh token, the new one is kept in memory and the stored
one stays the fallback; once the stored token is replaced in the vault,
the rotated one is no longer used. Token requests never follow a redirect
to another host. The client won't follow a redirect to another host
or from https to http, and errors never include tokens or the token
endpoint's description. Ids, folders and paths are checked and escaped
before they reach a URL. Subjects and addresses with line breaks, control characters,
Unicode line separators or bidirectional overrides are refused, so nothing
can add a header or make the preview read differently; an address must be
a plain `local@domain` with one `@` (no quoted local part), and a subject
that contains `=?` is encoded whole so it isn't decoded as an encoded word; the message is built as MIME and
sent through `sendMail`. Messages with `@channel`, `@team`, `@everyone` or
`<at>` tags are refused rather than notifying a whole channel.

## Notes

- Application permissions (app sign-in): `Mail.Read`, `Mail.Send`,
  `Calendars.ReadWrite`, `Files.Read.All`, with admin consent. Limit the
  app to the mailboxes it needs with an Exchange application access policy.
- Delegated permissions (user sign-in): `offline_access`, `Mail.Read`,
  `Mail.Send`, `Calendars.ReadWrite`, `Files.Read`,
  `ChannelMessage.Send`.
- Microsoft doesn't let an app post to Teams as itself, so
  `post_channel_message` works with the delegated sign-in only.
- Mail is sent as plain text without attachments.
- Refresh tokens expire after 90 days without use; sign in again then.
