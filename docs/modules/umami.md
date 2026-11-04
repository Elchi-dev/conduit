# Umami

Website analytics from Umami, self-hosted or Umami Cloud: websites, totals
over a period, visitors right now and the top pages, referrers and
countries. The module is read-only.

**Setup.** Self-hosted: enter the server's address (with a path if Umami is
served under one), a user name and the password's vault reference. A
view-only user is enough; the module signs in with `/api/auth/login` and
keeps the session token in memory only, signing in again when it expires.
Umami Cloud: leave the address empty and enter an API key (Settings, API
keys) from the vault instead. For a self-signed certificate, enter its
SHA-256 `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `websites` | read | Websites with ID, name, domain and creation date, including teams' websites. Never their share IDs. |
| `stats` | read | Pageviews, visitors, visits, bounce rate (%) and average visit time (seconds) of a `website` over a `period` ending now (`24h`, `7d`, `30d`, `90d`, `12mo`; 7d by default) or a custom `from`/`to` date range in UTC. |
| `active` | read | Visitors on a `website` in the last 5 minutes. |
| `top` | read | The top `limit` (up to 100, 10 by default) `page`, `referrer`, `country`, `browser`, `os`, `device` or `event` values by count over the same periods. Works with Umami 2 (`url`) and Umami 3 (`path`). |

**Security.** The password and API key are read from the vault per call;
the session token never appears in output. The client follows redirects
only within the same host and never from https to http. Website IDs must be
UUIDs, and periods, dates, metric types and limits are checked before they
reach a request.
