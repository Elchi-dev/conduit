# Brevo

Contact lists with subscriber counts, email campaigns and their statistics,
transactional email statistics, creating draft campaigns, sending tests and
sending campaigns in a [Brevo](https://www.brevo.com) (formerly Sendinblue)
account.

**Setup.** In Brevo open Settings, SMTP & API, API keys, create a key
(`xkeysib-…`) and store it in the vault. Optionally list `testRecipients`:
the addresses `send_test` may send to besides the account's own address.

| Action | Risk | Notes |
| --- | --- | --- |
| `lists` | read | Contact lists with subscriber, unique subscriber and blocklisted counts. Counts only, no addresses. |
| `campaigns` | read | Email campaigns, newest first (`status`: `draft`, `sent`, `queued` for scheduled, `suspended`, `archive`, `inProcess`; `limit` default 20), with subject, sender, lists, schedule and delivery, open and click counts. |
| `campaign` | read | One campaign's status, lists, exclusion lists and statistics. |
| `transactional_stats` | read | Transactional email totals over the last `days` (default 7): requests, delivered, opens, clicks, bounces, blocked, invalid, spam reports and unsubscribes. |
| `create_draft` | write | Creates a draft `name` with `subject`, `lists` (ids), optional `previewText` and `senderEmail` (one of the account's active senders; the only one by default), and either `text` or `html`. The preview names the lists with their counts and shows the content in full. Undo deletes the draft. |
| `delete_draft` | destructive | Deletes a draft campaign; anything else is refused. The preview names it. |
| `send_test` | write | Sends a test of a campaign to one address: the account's own, or one of `testRecipients`. Any other address is refused. |
| `send_campaign` | destructive | Sends a draft to its lists now. The preview names each list with its subscriber count, the exclusion lists, the subject and the sender. A campaign that has gone out answers "nothing to change". |

**Content.** `html` is sent as written; `text` becomes simple HTML (escaped,
a paragraph per block, line breaks kept). Either way the preview shows the
HTML in full, exactly as it will be sent. Script tags (remote or inline) are
refused, since email clients don't run them.

**Security.** The key goes in the `api-key` header and the client won't
follow a redirect to another host or from https to http. Ids, addresses and
one-line names and subjects (no header injection) are checked before any
request is made. Contacts' addresses are never read.

**Notes.** The preview's total adds up the lists, so a contact on two lists
counts twice, and exclusion lists are named rather than subtracted. Scheduled
campaigns are listed with their time; scheduling stays in Brevo.

**Presets.** team.
