# SolarEdge

One SolarEdge site through the monitoring API: power now and energy today,
this month, this year and over its lifetime, energy by meter per day or per
hour, and what the site is made of. Read-only.

**Setup.** In the monitoring portal, open Admin, Site Access and turn on API
Access; copy the API key into the vault and enter its `secret://` reference
as `apiKey`. `siteId` is the number shown next to the site's name (and in
the portal's address). An account-level key works too.

| Action | Risk | Notes |
| --- | --- | --- |
| `overview` | read | Power now (W), energy today, this month, this year and lifetime (kWh), lifetime revenue, what measures it (inverter or meter), the site's name, status and peak power (kWp), and when it last reported. |
| `energy` | read | Energy per meter the site has (production, consumption, self-consumption, feed-in, purchased) with totals. `unit` is `day` (default; up to 366 days, the last 7 by default) or `hour` (up to 31 days, today by default). `start` and `end` are dates like `2026-11-04`, in the site's local time. |
| `inventory` | read | Inverters (model, firmware, connected optimizers), batteries (model, capacity), meters, gateways and sensors, with counts. |

Health reports the site's name and peak power, and is `degraded` when the
site isn't active.

**Security.** SolarEdge takes the key only as a query parameter, so it is
added to each request at the last moment, connection errors show the
address without its query, and the client won't follow a redirect to
another host or from https to http. Dates are checked and the range
bounded before anything is sent. The site's address and coordinates and
the devices' serial numbers are never decoded.

**Notes.** SolarEdge allows 300 requests a day per site and key; a hit
limit is reported as such. Values for a period still in progress are
partial. A site without meters reports production only.
