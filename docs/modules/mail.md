# Mail

Any mailbox over IMAP and SMTP. Add one instance per address.

## Setting it up

Pick a provider and Conduit fills in the servers:

| Provider | IMAP | SMTP | Password |
| --- | --- | --- | --- |
| Gmail | imap.gmail.com:993 | smtp.gmail.com:465 | App password (Google account → Security → App passwords) |
| Outlook / Microsoft 365 | outlook.office365.com:993 | smtp.office365.com:587 | App password, if your account allows basic sign-in |
| iCloud | imap.mail.me.com:993 | smtp.mail.me.com:587 | App-specific password |
| Fastmail | imap.fastmail.com:993 | smtp.fastmail.com:465 | App password |
| Yahoo | imap.mail.yahoo.com:993 | smtp.mail.yahoo.com:465 | App password |
| Proton | Proton Mail Bridge on 127.0.0.1:1143 / 1025 | | Bridge password |
| Other | your servers | | |

Store the password in the vault and enter its reference (e.g.
`secret://mail/work`). Port 993/465 use TLS, 143/587 upgrade with STARTTLS;
plain connections are only allowed to Proton Bridge on this machine.

Sign-in with OAuth (no app password) is planned; providers that disable app
passwords for your account can't be connected until then.

## Actions

| Action | Risk | Notes |
| --- | --- | --- |
| `inbox` | read | Newest messages, optionally unread only |
| `search` | read | Text, sender, subject, last N days, unread |
| `read` | read | Plain text (HTML is converted to text, never rendered), recipients, attachment names. Doesn't mark it read. |
| `mailboxes` | read | Folders with message and unread counts and their role (sent, drafts, archive…) |
| `mark_read`, `mark_unread`, `flag`, `unflag` | write | Each undoes the other |
| `move` | write | Undo moves it back |
| `draft` | write | Saves to Drafts without sending |
| `send` | destructive | Dry run shows recipients, subject and body; replies thread with `replyToUid` |

Sending is destructive because it can't be recalled and speaks in your
name: with the default rules an agent always asks first, and the approval
shows exactly what will be sent.

## New mail

With **Announce new mail** on, Conduit checks every two minutes and publishes
`mail.received` with the new messages' senders and subjects. Use it in
automations, or for the daily brief.
