# Fathom Analytics

Website analytics from Fathom Analytics: sites, visits, unique visitors,
pageviews, average duration and bounce rate over a date range, grouped by
page, referrer, country, device and more or by date, and the visitors on a
site right now. The module is read-only.

**Setup.** In Fathom, open Settings, API and create an API key (a key
limited to reading the sites the module may use is a good fit). Store it in
the vault and enter its `secret://` reference as `apiKey`.

| Action | Risk | Notes |
| --- | --- | --- |
| `sites` | read | Site id, name and sharing setting. |
| `aggregation` | read | Any of `visits`, `uniques`, `pageviews`, `avg_duration` and `bounce_rate` (all by default) for the last `days` (30 by default, today included, UTC) or a `from`/`to` range of up to a year. In total, or grouped by up to three fields (`pathname`, `hostname`, `referrer_hostname`, `referrer_pathname`, `browser`, `country_code`, `device_type`, `operating_system` and the `utm_` fields), or by `hour`, `day`, `month` or `year` with `dateGrouping`. Sorted by the first aggregate, or by date. Up to `limit` rows (100 by default, at most 1000). |
| `current_visitors` | read | Visitors on the site now, with counts by page and by referrer. |

**Security.** The key goes as a Bearer token to Fathom's API only, and the
client won't follow a redirect to another host. Site ids, aggregates,
groupings, dates and limits are checked before a request is made; long
values are clipped and the output is capped.

## Notes

- A key with read access to the sites is enough; the module never writes.
- Fathom keeps no personal data, so every answer is already an aggregate.
- Aggregations cover pageviews; events aren't read.
