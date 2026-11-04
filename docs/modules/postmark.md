# Postmark

One [Postmark](https://postmarkapp.com) server: outbound stats, bounces,
message streams, and reactivating a bounced address with a preview.

**Setup.** In Postmark open Servers, your server, API Tokens, and copy the
**server API token** into the vault; enter its `secret://` reference. An
account token won't work (Postmark refuses it, and Health says so). Health
shows the server's name; the API tokens Postmark returns with it are never
read out.

| Action | Risk | Notes |
| --- | --- | --- |
| `stats` | read | The last `days` (default 30, up to 365), optionally for one message `stream` or `tag`: sent, bounced, SMTP API errors, bounce rate, spam complaints and their rate, opens, unique opens and clicks. |
| `bounces` | read, sensitive | Recent bounces (`count` up to 500, `offset`), optionally of one `type` (`HardBounce`, `SoftBounce`, `SpamComplaint`, …), only `inactive` ones or one `stream`: id, address, type, description, details, sender, subject, when, and whether the address was deactivated and can be reactivated. Message content is never returned. |
| `reactivate_bounce` | destructive, sensitive | Reactivates the address of a `bounce` (id) that deactivated it, so Postmark sends to it again. The preview names the address, the bounce type and date. An address that is active already is reported; one Postmark won't reactivate (spam complaints, some hard bounces) is refused before any change. No undo. |
| `message_streams` | read | Streams (transactional, broadcast, inbound) with type, description and unsubscribe handling; `includeArchived` for archived ones too. |

**Why reactivating is destructive.** A deactivated address is one that
hard-bounced or complained; sending to it again can reach someone who
asked not to be mailed, or hurt the server's reputation. Keep
`reactivate_bounce` on ask.

**Personal data.** Bounces name recipients, so `bounces` is sensitive, and
so is `reactivate_bounce`, whose preview names the address (both are kept
out of the audit log, approvals and events). `stats` and
`message_streams` carry no addresses.

**Safety.** The token goes in the `X-Postmark-Server-Token` header and the
client won't follow a redirect to another host. Bounce ids are numbers,
stream ids and bounce types are checked against their shapes and known
values, and tags must be one line, before a request is made.

**Presets.** developer, team.
