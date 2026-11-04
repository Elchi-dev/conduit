# Mailchimp

Audiences with their member counts, campaigns and their reports, creating
draft campaigns, sending tests, and scheduling, unscheduling or sending
campaigns in a [Mailchimp](https://mailchimp.com) account.

**Setup.** In Mailchimp open Profile, Extras, API keys, create a key and
store it in the vault. The key ends in your account's data center (like
`…-us21`), which Conduit reads to reach the right API host. Optionally list
`testRecipients`: the addresses `send_test` may send to besides the account
owner's own address.

| Action | Risk | Notes |
| --- | --- | --- |
| `audiences` | read | Each audience with subscribed, unsubscribed and cleaned counts, campaign count and default sender. Counts only, no addresses. |
| `campaigns` | read | Campaigns, newest first (`status`: `save` for drafts, `paused`, `schedule`, `sending`, `sent`; `limit` default 20), with title, subject, audience, recipient count, send time and open and click rates. |
| `campaign_report` | read | A sent campaign's emails sent, opens, clicks (total and unique), bounces, unsubscribes and abuse reports. |
| `create_draft` | write | Creates a draft for one `audience` with `subject`, optional `title`, `previewText`, `fromName` and `replyTo` (the audience's sender by default), and either `text` (a plain-text campaign) or `html`. The preview shows the content in full. Undo deletes the draft. |
| `delete_draft` | destructive | Deletes a draft campaign; sent and scheduled campaigns are refused. The preview names it. |
| `send_test` | write | Sends a test of a campaign to one address: the account owner's, or one of `testRecipients`. Any other address is refused. |
| `schedule_campaign` | destructive | Schedules a draft for `at` (RFC 3339, on a quarter hour as Mailchimp requires). The preview names the audience, its recipient count, the subject and the sender. Undo unschedules it. |
| `unschedule_campaign` | write | Turns a scheduled campaign back into a draft. Undo schedules it again for the same time (and asks again, since scheduling is destructive). |
| `send_campaign` | destructive | Sends a draft to its audience now. The preview names the audience, its recipient count, the subject and the sender. |

Scheduling a campaign for the time it already has, unscheduling a draft and
sending a campaign that has gone out each answer "nothing to change".

**Content.** `text` makes a plain-text campaign; `html` a regular one, from
which Mailchimp derives the plain-text part. HTML is authored content, so the
preview shows it exactly as it will be sent. Script tags (remote or inline)
are refused, since email clients don't run them.

**Security.** The key's data center suffix must be letters followed by
digits before the host `<dc>.api.mailchimp.com` is built, so a crafted key
can't send the request, or the key, anywhere else. The key goes in the
`Authorization` header, and the client won't follow a redirect to another
host. Ids, times, addresses and one-line subjects and names (no header
injection) are checked before any request is made. Subscriber addresses are
never read.

**Notes.** A campaign sent to a segment shows Mailchimp's own recipient count
for it. RSS, A/B and automated campaigns can be listed and reported on, while
sending them stays in Mailchimp.

**Presets.** team.
