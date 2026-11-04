# SendGrid

A [Twilio SendGrid](https://sendgrid.com) account (or subuser): delivery
stats, the suppression lists, templates, and removing an address from a
suppression list with a preview.

**Setup.** In SendGrid open Settings, API Keys, and create a key with
**Restricted Access**: Stats read, Suppressions read and Templates read;
Suppressions full access only if agents may remove suppressions. Store it
in the vault and enter its `secret://` reference. Set `region` to `eu` for
an EU regional subuser (the default is `global`). Health reads the key's
permissions: it's degraded without Stats read, and says so when the key
has full access.

| Action | Risk | Notes |
| --- | --- | --- |
| `stats` | read | The last `days` (default 7, up to 90): totals and daily rows of requests, processed, delivered, deferred, bounces, blocks, spam reports, invalid emails, unsubscribes, the matching drops, opens and clicks, with the delivered rate. |
| `suppressions` | read, sensitive | One `list` (`bounces`, `blocks`, `spam_reports`, `invalid_emails`, or `unsubscribes` for global unsubscribes; `limit` up to 500): address, date, reason and status. Spam report IPs are never returned. |
| `delete_suppression` | destructive, sensitive | Removes `email` from a `list`, so SendGrid sends to it again: someone who bounced, was blocked, reported spam or unsubscribed. The preview shows the entry. An address that isn't on the list is reported, not an error. No undo. |
| `templates` | read | Dynamic and legacy templates (`limit` up to 200) with their number of versions and the active one. Template content isn't returned. |

**Why removing a suppression is destructive.** It can get mail to someone
who unsubscribed or reported spam, and hurt the sender's reputation. Keep
`delete_suppression` on ask.

**Personal data.** Suppression lists name recipients, so `suppressions`
and `delete_suppression` are sensitive (kept out of the audit log,
approvals and events). `stats` and `templates` carry no addresses.

**Safety.** The key goes in the `Authorization` header and the client
won't follow a redirect to another host. Lists are checked against their
known names and addresses as one plain address (escaped into the path)
before a request is made.

**Presets.** developer, team.
