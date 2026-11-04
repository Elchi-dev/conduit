# Matomo

Website analytics from Matomo, self-hosted or Matomo Cloud, through its
Reporting API: sites, a visits summary over a period, the top pages and
referrers, and the visitors of the last minutes. The module reads
aggregates only and is read-only.

**Setup.** In Matomo, open Administration, Personal, Security and create an
auth token for a user with view access to the sites the module may read
(a dedicated user with only view access is a good fit). Store the token in
the vault. Enter your Matomo's address, such as
`https://matomo.example.com`, with its path if it's served under one. For a
self-signed certificate, enter its SHA-256 `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `sites` | read | Site id, name, main URL, time zone, currency and whether it's an ecommerce site. |
| `visits_summary` | read | Visits, unique visitors, users, actions, actions per visit, bounce rate (%), average time on site (seconds) and converted visits. The `period` (`day`, `week`, `month` by default, `year`) contains `date` (`today` by default, `yesterday` or `YYYY-MM-DD`); or give a `from`/`to` range of up to a year. |
| `top_pages` | read | The most visited page URLs (without their query, shown as `?…`, since a query can hold one visitor's details), with visits, pageviews, average time on page, bounce and exit rates. Same periods; up to `limit` rows (10 by default, at most 1000). |
| `top_referrers` | read | Where visits came from (search engines, websites, campaigns, social networks), with the referrer type and visits. Same periods and limit. |
| `live` | read | Visits, visitors, actions and converted visits in the last `minutes` (30 by default, at most 1440). |

**Security.** The token is sent in the body of a POST request, never in a
URL, so it can't end up in a server log, a proxy log or an error message
quoting the address; errors from Matomo are scrubbed of it and of anything
else credential-like. The client won't follow a redirect to another host or
from https to http. Site ids, periods, dates and limits are checked before
a request is made; long values are clipped and the output is capped.

## Notes

- The token's user needs **view** access to each site; nothing more is
  used.
- The module never reads single visits: no visitor log, IP addresses,
  visitor or user ids. `live` returns counts only.
