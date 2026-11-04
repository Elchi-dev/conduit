# Resend

A [Resend](https://resend.com) account: sending domains with their
verification status and DNS records, recently sent emails with their
delivery status, audiences with contact counts, and test emails to
addresses you allow-list in the settings.

**Setup.** In Resend open API Keys, create a key with **Full access**
(a sending-only key can't read domains or emails; Health says so), store
it in the vault and enter its `secret://` reference. To use
`send_test_email`, also set `from` (a sender at one of your verified
domains, e.g. `Conduit <test@example.com>`) and `testRecipients`: up to 10
plain addresses, such as yours or a team inbox. Test emails go only to
those addresses; anything else is refused before a request is made. Health
shows how many domains are verified, and is degraded when none is.

| Action | Risk | Notes |
| --- | --- | --- |
| `domains` | read | Domains with status (`not_started`, `pending`, `verified`, `failed`, `temporary_failure`) and region. |
| `domain` | read | One domain (`id`): its status and each DNS record (SPF, DKIM, MX) Resend checks, with name, value, TTL, priority and its own status, plus how many aren't verified yet. |
| `emails` | read, sensitive | Recently sent emails, newest first (`limit` up to 100, `after` for the next page): recipients, sender, subject, the last event (`delivered`, `bounced`, `complained`, `opened`, …) and the schedule. Bcc recipients are counted, not named; bodies are never returned. |
| `audiences` | read | Audiences with how many contacts each has, subscribed and unsubscribed. Counts only, no addresses. An audience is counted up to 2,000 contacts (`atLeast` marks a larger one), and the first 20 audiences are counted. |
| `send_test_email` | write, sensitive | Sends a short plain-text email from `from` to `to`, which must be one of `testRecipients` (it may be left out when there's only one). Optional one-line `subject` and `text` (up to 5,000 characters). The preview shows sender, recipient, subject and text. No undo: a sent email can't be recalled. |

**Personal data.** Recipient addresses and message content are kept out
of the audit log, approvals and events: `emails` and `send_test_email`
are sensitive, and the other actions return no addresses. Error messages
from Resend are redacted of anything that looks like a credential.

**Safety.** The key goes in the `Authorization` header and the client
won't follow a redirect to another host. Domain and page ids are checked
as UUIDs, recipients against the allow-list (case-insensitively, one
address, no names or lists), and subjects for line breaks before a request
is made. Each send carries a random `Idempotency-Key`. A rate-limited read
(429) is retried once after Resend's `Retry-After` (up to 2 seconds).
Sending is `write` because it can reach only the addresses the owner put
in the settings; keep it on ask if those include shared inboxes.

**Presets.** developer, team.
