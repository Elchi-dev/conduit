# Daily brief

One summary of what needs you: systems that are down or degraded, approvals
waiting, unread mail per account (latest five), today's events, actions that
failed in the last 24 hours and API keys expiring within a week.
With a [weather](weather.md) instance set up, it also has a line per place:
now, today's low and high, and the chance of rain in the next 12 hours.

| Action | Risk | Notes |
| --- | --- | --- |
| `brief` | read | The summary, for the app or an agent |
| `send` | write | Sends it to the channels in settings, or every notification channel. The preview shows the exact title and text each channel gets (the generic line for a channel set to hide details) |

The quickest way to get one every morning: **Automations → Get a morning
brief → Turn on** (7:30 on weekdays, your time zone).

**Whose brief it is.** The brief is built for whoever asks for it and reads
other modules as them, through the engine, so each read appears in the
timeline under their name and the policy applies as to a direct call:

- A section whose read the policy doesn't allow the caller outright (denied,
  or one that would ask) is left out, and so is the health line of a
  connection the caller may read nothing of. A brief never files approvals
  for its reads.
- Approvals waiting need `approvals:*:read`; expiring keys need
  `keys:*:manage` and are the caller's own person's keys.
- Failures in the last 24 hours come from the audit log, so only for a
  caller with `audit:*:read`, and only as module and action, never the
  error text.
- `send` delivers through each channel's own `send` action, again as the
  caller: a channel the caller may not use is refused (`refused`), one that
  needs approval files it (`waitingForApproval`).
- A scheduled brief, run by an automation that a person saved or turned on,
  acts as that person (who saved it last). An automation drafted by an
  agent or key acts as itself, under its own rules, with no audit log.
