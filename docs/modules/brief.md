# Daily brief

One summary of what needs you: systems that are down or degraded, approvals
waiting, unread mail per account (latest five), today's events, actions that
failed in the last 24 hours and API keys expiring within a week.
With a [weather](weather.md) instance set up, it also has a line per place:
now, today's low and high, and the chance of rain in the next 12 hours.

| Action | Risk | Notes |
| --- | --- | --- |
| `brief` | read | The summary, for the app or an agent |
| `send` | write | Sends it to the channels in settings, or every notification channel |

The quickest way to get one every morning: **Automations → Get a morning
brief → Turn on** (7:30 on weekdays, your time zone). The brief reads other
modules as Conduit itself, so each read appears in the timeline.
