# Google Workspace

Gmail, Google Calendar and Google Drive for a Workspace or personal Google
account: list, read and send mail, see and add events, schedule meetings
and find files.

**Setup.** In the Google Cloud Console, enable the Gmail, Google Calendar
and Google Drive APIs for a project. Then pick a sign-in:

- **OAuth** (any Google account): create an OAuth client (APIs & Services,
  Credentials), sign in once with the scopes below and offline access, and
  store the client secret and the refresh token in the vault. Enter the
  client id, `clientSecret` and `refreshToken`.
- **Service account** (Workspace): create a service account, download its
  JSON key and store the whole file in the vault as `serviceAccount`. In
  the Admin console, open Security, API controls, Domain-wide delegation,
  and authorize the service account's client id for the scopes below. Set
  `subject` to the user the module acts as.

`calendar` sets the calendar used when an action names none (`primary` by
default).

| Action | Risk | Notes |
| --- | --- | --- |
| `mail_list` | read | Newest messages matching a Gmail search (`query`, default `in:inbox`), up to 25: sender, subject, date, snippet, unread. Sensitive. |
| `mail_read` | read | Sender, recipients, subject, date, the plain text (HTML reduced to text, never rendered) and attachment names. Doesn't mark it read. Sensitive. |
| `send_mail` | destructive | A plain-text message to `to`, `cc` and `bcc` (50 recipients at most). The preview shows recipients, subject and body. Sensitive. |
| `events` | read | Events in the next `days` (7 by default, up to 60): title, start, end, location, organizer, attendees with their answers, Meet link. Sensitive. |
| `create_event` | write | A private event without attendees; nobody is notified. Undo deletes it. Sensitive. |
| `schedule_meeting` | destructive | An event with `attendees`, each emailed an invitation; `online` adds a Google Meet link. Undo deletes it, which sends a cancellation. Sensitive. |
| `delete_event` | destructive | Deletes an event and notifies its attendees. The preview shows its time and attendee count, never the title or names. An event that's already gone is "nothing to change". |
| `files` | read | Drive files, newest first: name, type, size, modified, link. Filter by `folder` id and by words in the `name`. Sensitive. |

Every action that returns mail, events or file names is sensitive, so the
audit log, approvals and events keep only its shape.

**Security.** Credentials are only accepted as `secret://` references. The
service account signs its own RS256 assertion; the key's `token_uri` is
never used. Access tokens live in memory per instance until shortly before
they expire, and a refused one is dropped and fetched again once. The
client won't follow a redirect to another host or from https to http, and
errors never include tokens or Google's error description. Ids and
calendar names are checked and escaped, and Drive search terms are quoted,
before any request. Subjects and addresses with line breaks are refused,
so nothing can add a header; the message is built as MIME, and Gmail drops
the Bcc header on delivery.

## Notes

- Scopes to grant (OAuth consent, or domain-wide delegation):
  `https://www.googleapis.com/auth/gmail.readonly`,
  `https://www.googleapis.com/auth/gmail.send`,
  `https://www.googleapis.com/auth/calendar.events`,
  `https://www.googleapis.com/auth/drive.metadata.readonly`.
  With domain-wide delegation all four must be authorized, since the module
  asks for them together.
- An OAuth client in "Testing" publishing status gets refresh tokens that
  expire after 7 days; publish the app (or use a Workspace internal app)
  for a lasting one.
- Mail is sent as plain text without attachments. Drive access is file
  metadata only: names, types and links, never content.
