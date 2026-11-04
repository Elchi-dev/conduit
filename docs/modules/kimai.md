# Kimai

Projects, activities and timesheets in Kimai, and starting or stopping a
timer.

**Setup.** In Kimai, open your avatar menu, API access, create an API token
and store it in the vault. Enter Kimai's address, such as
`https://time.example.com` (or your Kimai Cloud address). The token acts as
your user. For a self-signed certificate, set `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `projects` | read | Visible projects: id, name, customer, order number and whether they're billable. `query` filters by project or customer. Sensitive, since it names customers. |
| `activities` | read | Visible activities: id, name, and their project or whether they're global. `project` lists that project's activities with the global ones. |
| `timesheets` | read | Your entries between `start` and `end` (the last 7 days by default, up to `limit`): project, activity, begin, end, duration, description and tags, with the total. `running` lists only the timers running now. |
| `start_timer` | write | Starts a timer now on `project` and `activity`, with an optional `description` and `tags`. Undo stops it. |
| `stop_timer` | write | Stops the timer `id`, or the only one running when no id is given. Undo starts a new timer on the same project and activity. |

Starting a timer that's already running on the same project and activity,
or stopping one that isn't running, reports that there's nothing to change.
Both changes have a preview. The timer starts in your Kimai time zone, since
Kimai sets the start time itself.

**Security.** The token goes in the `Authorization` header, and the client
won't follow a redirect to another host or from https to http. Ids, dates
and tags are checked before any request. Rates, budgets and the user are
never read.

**Notes.** When Kimai allows only one running timer, it stops the previous
one on a start; the preview mentions any timers already running. The undo of
a stop is a new entry, not the old one reopened.
