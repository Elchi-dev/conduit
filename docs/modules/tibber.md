# Tibber

Your Tibber homes, the electricity price now and for today and tomorrow,
and consumption over the last hours or days, through Tibber's GraphQL API.
Read-only.

**Setup.** Sign in at [developer.tibber.com](https://developer.tibber.com),
open Settings and create a personal access token; store it in the vault and
enter its `secret://` reference as `token`.

| Action | Risk | Notes |
| --- | --- | --- |
| `homes` | read | Id, nickname, type (house, apartment, …), time zone, the subscription's status, and whether live data (Pulse or Watty) is on. |
| `prices` | read | The price now (total, energy, tax, level from `very_cheap` to `very_expensive`) and today's and tomorrow's prices, each day with its average, cheapest and dearest slot. `home` picks a home (default: the first). |
| `consumption` | read | Energy used, cost and unit price per period, with the totals. `resolution` is `hourly` (default, `last` 24, up to 744 = 31 days) or `daily` (default `last` 7, up to 366). |

Health reports how many homes the account has and how many have a running
subscription.

**Security.** The token goes in the `Authorization` header, and the client
won't follow a redirect to another host or from https to http. Queries are
fixed; the home id, resolution and count travel as GraphQL variables, and
the home id is checked as a plain identifier first. Addresses, coordinates
and the account owner are never asked for. Error text from Tibber is
redacted before it's shortened.

**Notes.** Tomorrow's prices are published around 13:00 CET; before that,
`tomorrow` is empty with a note. Consumption needs a running subscription
with metering data; periods without data come back without a value.
