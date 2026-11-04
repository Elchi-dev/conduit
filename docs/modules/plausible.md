# Plausible Analytics

Website analytics from Plausible, on plausible.io or a self-hosted Plausible
Community Edition, through the Stats API v2: sites, visitors right now,
totals over a period and the top pages, sources and countries. The module is
read-only.

**Setup.** Create a Stats API key (Account settings, API keys) and store it
in the vault. Leave the address at `https://plausible.io`, or enter your
server (with a path if Plausible is served under one). Listing sites needs
a key that may use the Sites API; otherwise, or to narrow what the instance
may read, list the site domains in `sites`. Sites outside that list are
refused before any request. For a self-signed certificate, enter its
SHA-256 `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `sites` | read | Site domains with time zone, from the Sites API (narrowed to `sites` when set); when the key can't list sites, the sites from the settings. |
| `realtime` | read | Unique visitors on a `site` in the last 5 minutes. |
| `aggregate` | read | Visitors, visits, pageviews, views per visit, bounce rate (%) and average visit duration (seconds) over a `period` (`day`, `7d`, `30d`, `month`, `6mo`, `12mo`, `year`, `all`; 30d by default) or a custom `from`/`to` date range (up to five years). |
| `breakdown` | read | The top `limit` (up to 100, 10 by default) `page`, `entry_page`, `exit_page`, `source`, `referrer`, `country`, `device`, `browser` or `os` values by visitors, with pageviews, over the same periods. |

**Security.** The key goes as a Bearer token, and the client follows
redirects only within the same host and never from https to http. Site
domains, periods, dates, breakdowns and limits are checked before they
reach a request; long values from the server are clipped. Plausible keeps
no personal data, so nothing here is marked sensitive.
