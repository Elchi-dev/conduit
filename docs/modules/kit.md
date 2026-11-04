# Kit

Subscriber counts, tags, broadcasts and their stats, creating draft
broadcasts, and scheduling or unscheduling them in a
[Kit](https://kit.com) (formerly ConvertKit) account, through the v4 API.

**Setup.** In Kit open Settings, Developer, API keys, create a v4 API key
and store it in the vault.

| Action | Risk | Notes |
| --- | --- | --- |
| `subscribers_count` | read | Subscribers by `status` (`active` by default, or `inactive`, `bounced`, `complained`, `cancelled`, `all`), in all or with one `tag`. Counts only, no addresses. |
| `tags` | read | Tags with their ids, for targeting a broadcast. |
| `broadcasts` | read | Broadcasts, newest first (`limit` default 20), with subject, status (`draft`, `scheduled` or `sent`), send time, recipients and whether it's public. |
| `broadcast_stats` | read | One broadcast's recipients, opens and open rate, clicks and click rate, unsubscribes and sending status. |
| `create_draft` | write | Creates a draft with `subject`, optional `previewText`, `description` and `emailAddress`, for all subscribers or the subscribers with any of `tags`, from `text` or `html`. Drafts are never public. The preview shows the content in full. Undo deletes the draft. |
| `delete_draft` | destructive | Deletes a draft broadcast; anything else is refused. The preview names it. |
| `schedule_broadcast` | destructive | Schedules a draft for `at` (RFC 3339). The preview names the recipients (all subscribers, or each tag with its count), the subject, the sender and whether it's also posted publicly. Undo unschedules it. |
| `unschedule_broadcast` | write | Turns a scheduled broadcast back into a draft. Undo schedules it again for the same time (and asks again). |

Scheduling for the time a broadcast already has, unscheduling a draft and
scheduling one that has gone out each answer "nothing to change".

**Content.** `html` is sent as written; `text` becomes simple HTML (escaped,
a paragraph per block, line breaks kept). The preview shows it in full.
Script tags (remote or inline) are refused, since email clients don't run
them.

**Security.** The key goes in the `X-Kit-Api-Key` header and the client
won't follow a redirect to another host or from https to http. Ids, times,
addresses and one-line subjects (no header injection) are checked before any
request is made. Subscribers' addresses and names are never read. Scheduling
sends the broadcast's other fields back unchanged.

**Notes.** A broadcast counts as sent once its send time has passed. Only
broadcasts for all subscribers or for tags can be scheduled here, since those
are the recipients Conduit can count; broadcasts using segments or exclusions
are scheduled in Kit. Several tags are added up, so a subscriber with two of
them counts twice.

**Presets.** team.
