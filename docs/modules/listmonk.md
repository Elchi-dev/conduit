# listmonk

A [listmonk](https://listmonk.app) newsletter server (v4 or later): lists and
subscriber counts, campaigns with status and stats, creating draft campaigns,
sending, pausing and deleting them.

**Setup.** In listmonk go to Admin, Users, create a user of type API with a
role that can read lists and subscribers and manage campaigns, and copy its
token into the vault. Enter the `address` (with a path if listmonk is served
under one), the API user's `username` and the token's `secret://` reference.
For a self-signed certificate, enter its SHA-256 `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `lists` | read | Lists with type, opt-in, subscriber counts by status and `reach`: how many a campaign would email (confirmed subscribers on double opt-in lists, everyone not unsubscribed otherwise). |
| `subscribers_count` | read | Subscribers in all, or on one `list`, optionally with a subscription `status`. Counts only, no addresses. |
| `campaigns` | read | Campaigns, newest first (`status` to narrow, `limit` default 20), with lists, sent and to-send counts, views, clicks and bounces. |
| `campaign` | read | One campaign's status and stats, with the send rate while it runs. |
| `create_campaign` | write | Creates a **draft** `name` with `subject`, `lists` (ids), `body` and `contentType` (`markdown` by default, or `richtext`, `html`, `plain`), optional `fromEmail`, `templateId` and `tags`. Nothing is sent. The preview names the lists with their reach; undo deletes the draft. |
| `send_campaign` | destructive | Starts a draft, scheduled or paused campaign: it emails every subscriber on its lists, which can't be recalled. A draft with a future send time is scheduled instead, and so is a paused campaign given `sendAt` (its unchanged, still future send time). The preview shows the subject, each list's reach and the total. |
| `pause_campaign` | write | Pauses a running or scheduled campaign; emails already sent stay sent. Undo goes through `send_campaign` (which asks again): a running campaign resumes (sending the rest), a scheduled one is scheduled again for its original send time rather than sent now. |
| `delete_campaign` | destructive | Deletes a campaign that isn't running, with its stats. The preview names it. |

**Security.** The token goes in the `Authorization` header and the client
won't follow a redirect to another host. Ids, statuses, content types, tags,
the from address and one-line names and subjects (no header injection) are
checked before a request is made.

**Presets.** team, homelab.
