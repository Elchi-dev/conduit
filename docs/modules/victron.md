# Victron VRM

Victron Energy installations through the VRM portal's API: the
installations you can see, the latest battery, solar, grid and consumption
values, and alarms. Read-only.

**Setup.** In VRM, open Preferences, Integrations, Access tokens and create
a token; store it in the vault and enter its `secret://` reference as
`token`. The token sees what its user sees.

| Action | Risk | Notes |
| --- | --- | --- |
| `installations` | read | Id (`site`), name, time zone, whether an alarm is active, mains and generator, its kind (boat, house, …) and when it last reported. |
| `summary` | read | Battery state of charge, voltage, current, power and state; PV power (DC- and AC-coupled, and the total); grid power (positive: drawing from the grid); generator and consumption power; and when they were logged. `all: true` adds every diagnostic value by device (up to 200). |
| `alarms` | read | Whether an alarm is active now, and the alarm rules: what each watches, low and high thresholds, delay before notifying, and whether it's on. |

`site` may be left out when the account has a single installation. The
summary reads the GX device's system totals (Venus OS `com.victronenergy.system`),
so it matches what the VRM dashboard shows.

Health reports how many installations there are, and is `degraded` when one
has an active alarm.

**Security.** The token goes in the `X-Authorization` header, and the client
won't follow a redirect to another host or from https to http.
Installation ids are checked as numbers before they reach a request path.
The user's name and e-mail, the people an alarm notifies, and an
installation's location, phone number and notes are never decoded.
`all: true` leaves out GPS values (latitude, longitude, altitude: a boat's
or camper's position, or the house) and anything naming a serial, a MAC or
IP address, a remote support port or another identifier; the remaining
values are redacted and clipped.

**Notes.** Values are as fresh as the GX device's last upload to VRM
(usually every few minutes); `loggedAt` says when. Installations without a
GX device logging system values give an empty summary with a note.
