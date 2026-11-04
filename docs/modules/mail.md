# Mail

Any mailbox over IMAP and SMTP, Proton Mail through Proton Mail Bridge
included. Add one instance per address. Nothing here is specific to one
provider: a preset only fills in settings, and every setting can be changed,
so moving from Proton to another provider later is a settings change.

## Setting it up

Pick a provider and Conduit fills in the servers:

| Provider | IMAP | SMTP | Password |
| --- | --- | --- | --- |
| Gmail | imap.gmail.com:993 | smtp.gmail.com:465 | App password (Google account → Security → App passwords) |
| Outlook / Microsoft 365 | outlook.office365.com:993 | smtp.office365.com:587 | App password, if your account allows basic sign-in |
| iCloud | imap.mail.me.com:993 | smtp.mail.me.com:587 | App-specific password |
| Fastmail | imap.fastmail.com:993 | smtp.fastmail.com:465 | App password |
| Yahoo | imap.mail.yahoo.com:993 | smtp.mail.yahoo.com:465 | App password |
| Proton Mail Bridge | 127.0.0.1:1143, STARTTLS | 127.0.0.1:1025, STARTTLS | The password Bridge shows for the account |
| Other | your servers | | |

Store the password in the vault and enter its reference (e.g.
`secret://mail/work`).

**Connection security.** Ports 993 and 465 use TLS from the start; other
ports upgrade with STARTTLS, and STARTTLS is required (a server that doesn't
offer it is refused). Set `security` (and `smtpSecurity` if SMTP differs) to
`tls`, `starttls` or `none`. `none` is accepted only for a server on this
machine (127.0.0.1, ::1 or localhost); Conduit refuses the settings
otherwise.

**Certificate trust.** `tlsTrust: system` (the default for every provider but
Proton) checks the server's certificate against the operating system's
authorities, as a browser would. `pinned` trusts exactly one certificate,
identified by its SHA-256 fingerprint. Certificate checks are never turned
off.

## Proton Mail Bridge

Bridge runs on your computer and serves your Proton mailbox over IMAP and
SMTP with a certificate it made itself, which no authority vouches for.
Choosing **Proton Mail Bridge** sets:

- servers 127.0.0.1, IMAP 1143 and SMTP 1025, both with STARTTLS;
- certificate trust **pinned**;
- labels as folders under `Labels/` (see below);
- sent mail not copied to Sent (Bridge files it there itself).

Enter your Proton address and, as the password, the one Bridge shows for the
account in its mailbox settings, not your Proton password. If
you changed Bridge's ports, enter them.

The certificate is pinned one of two ways:

1. **Trust on first use** (nothing to do). The first connection records the
   certificate's fingerprint, and from then on only that certificate is
   accepted, for IMAP and SMTP separately. Health shows the fingerprint
   ("certificate pinned on first use SHA-256 AB:CD:…"); `tls_status` shows
   it with the certificate's subject and expiry, so you can compare it with
   what Bridge exports.
2. **Paste the certificate.** In Bridge: Settings, Advanced settings, Export
   TLS certificates. Paste the contents of `cert.pem` into **Pinned
   certificate**, or its fingerprint into **Pinned SHA-256 fingerprint**
   (`openssl x509 -in cert.pem -noout -fingerprint -sha256` prints it). A
   pin in the settings can't be changed by an agent.

If the certificate changes (Bridge was reinstalled or regenerated it),
connections fail with a message naming the old and the new fingerprint.
Check the new one against Bridge's export, then either paste the new
certificate, or call `trust_certificate` with the fingerprint (`tls_status`
shows what the server presents now); its undo restores the previous pin.
If you didn't change anything on your side, don't trust it: something else
may be answering on Bridge's port.

Pins taken on first use are kept with the instance's state in the daemon's
data folder (`modules/mail/<instance>.json`); they are not secrets.

## Actions

Messages are addressed by `uid` and `mailbox` (default `INBOX`), as listed by
`inbox`, `search` and `thread`. Uids change when a message moves; the moving
actions return the new ones. Most actions that change messages also take
`uids` for several at once.

| Action | Risk | Notes |
| --- | --- | --- |
| `inbox` | read | Newest messages in a folder, optionally unread only |
| `search` | read | IMAP SEARCH: `from`, `to`, `cc`, `subject`, `body`, `text` (anywhere), `since`/`before` (YYYY-MM-DD) or `sinceDays`, `unread` (true/false), `flagged`. All given conditions must match. |
| `read` | read, sensitive | Headers (Message-ID, In-Reply-To, References, Reply-To), text (HTML converted to text, never rendered; links keep their address), attachment list. Doesn't mark it read. |
| `thread` | read | The conversation, found by References and In-Reply-To across this folder, the inbox, Sent and Archive, oldest first |
| `download_attachment` | read, sensitive | One attachment as base64, by `index` or `name`, up to `maxMB` (10, at most 25) |
| `mailboxes` | read | Folders and labels with message and unread counts, role (inbox, sent, drafts, trash, archive, junk) and kind (system, folder, label) |
| `unread_counts` | read | Unread in the inbox, and in every folder that has any |
| `drafts` | read | Messages in Drafts |
| `mark_read`, `mark_unread`, `flag`, `unflag` | write | Each undoes the other |
| `move`, `copy` | write | Undo moves it back, or removes the copy |
| `archive` | write | Moves to Archive (or, without one, All Mail); undo moves it back |
| `label`, `unlabel` | write | See labels below; each undoes the other. `create` makes a missing label. |
| `delete` | destructive | Preview lists the messages. Moves to Trash; undo moves them back. In Trash, or with `permanent`, the messages are erased, which can't be undone. |
| `send` | write, sensitive | New message: `to`, `cc`, `bcc`, `subject`, `body`, optional `html` and `attachments` |
| `reply`, `reply_all` | write, sensitive | `Re:` subject, In-Reply-To and References set, original quoted (`quote: false` to leave it out). Reply all goes to the sender and everyone in To and Cc except you. Marks the original answered. |
| `forward` | write, sensitive | `Fwd:` subject, the original's headers and text below your note, its attachments included (`includeAttachments: false` to leave them) |
| `draft` | write, sensitive | Saves to Drafts (APPEND) and returns its uid |
| `update_draft` | write, sensitive | Changes the fields you give; the rest stays. The draft gets a new uid. |
| `send_draft` | write, sensitive | Sends a draft (threading kept) and removes it from Drafts |
| `delete_draft` | destructive | |
| `tls_status` | read | The certificates IMAP and SMTP present, the pins, whether they match |
| `trust_certificate` | write | Pin a fingerprint for `imap`, `smtp` or `both`; empty forgets the pin. Undo restores the previous one. |

`reply`, `reply_all` and `forward` take `draft: true` to save to Drafts
instead of sending.

**Sending.** Every sending action has a preview: the approval shows the
sender, every recipient (Bcc too), subject, body (up to 4,000 characters),
attachments with their sizes, and what it replies to. Sending is `write`, so
the default rules ask before an agent sends; tighten it per action in the
rules if you like. Mail can't be recalled once sent, so there is no undo.

**Sensitive.** Actions that carry message content (`read`,
`download_attachment` and the sending and draft actions) are marked
sensitive: their input and output never reach the audit log, approvals or
events, only the preview does.

**Attachments** are given as `{"name", "base64"}`, or as `{"path"}` relative
to the mailbox's **attachments folder** (`attachmentsDir`, for example the
Files module's folder). Paths can't leave that folder. All attachments of one
message together are capped at `maxAttachmentMB` (25 by default, at most 50).

**Labels.** With `labelMode: folders` (Proton, Gmail) a label is a folder:
labelling copies the message into `<labelPrefix><label>` (`Labels/Work` on
Proton) and removing the label erases that copy, which on Proton removes the
label and leaves the message where it was. With `labelMode: keywords` (other
servers) a label is an IMAP keyword on the message. Proton's own folders are
under `Folders/`; use `move` for those.

**Deleting on Proton.** Deleting from a label folder (`Labels/…`) in Bridge
removes the label only; delete from the inbox or a folder to move a message
to Trash.

## New mail and unread counts

With **Announce new mail** on, Conduit checks the inbox every
`watchSeconds` (120 by default, at least 30) and publishes:

- `mail.received` with `count`, the inbox's `unread` count and the new
  messages' senders, subjects and uids;
- `mail.unread` with `unread` and `previous` whenever the inbox's unread
  count changes (read elsewhere, new mail, deleted).

The position is kept across restarts, so mail that arrived while the daemon
was off is announced once (up to 50 messages). Use the events in
automations, or for the daily brief. The check uses STATUS and fetches only
new uids; it polls rather than holding an IDLE connection, which works the
same on every server, Bridge included.

Sign-in with OAuth (no app password) is planned; providers that disable app
passwords for your account can't be connected until then.
