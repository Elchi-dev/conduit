# Google Search Console

Search performance from Google Search Console: the sites a service account
can see, clicks, impressions, click-through rate and average position by
search query, page, country, device or date, and the submitted sitemaps.
The module is read-only.

**Setup.** In the Google Cloud Console, pick or create a project, turn on
the Google Search Console API, create a service account and download a JSON
key for it. Store the whole key file in the vault and enter its `secret://`
reference as `serviceAccount`. Then, in Search Console, open Settings,
Users and permissions for each property and add the service account's email
(the key's `client_email`); the Restricted permission is enough.

| Action | Risk | Notes |
| --- | --- | --- |
| `sites` | read | Each property (`sc-domain:example.com` or `https://www.example.com/`) with the service account's permission level. |
| `search_analytics` | read | Clicks, impressions, CTR and average position, in total or grouped by up to three of `query`, `page`, `country`, `device`, `date` and `searchAppearance`, sorted by clicks. Covers the last `days` (28 by default) or a `from`/`to` range of up to 16 months, for the `type` `web` (default), `image`, `video`, `news`, `discover` or `googleNews`. Up to `limit` rows (100 by default, at most 1000). |
| `sitemaps` | read | Each submitted sitemap: path, type, when it was submitted and last downloaded, whether it's pending or an index, error and warning counts, and submitted URLs by content type. |

**Security.** The service account signs a JWT with its key and exchanges it
at Google's token endpoint for a read-only access token, kept in memory
until shortly before it expires; the key file's own `token_uri` is never
used. Calls go only to Google's API host, and the client won't follow a
redirect to another host. Sites, dimensions, dates and limits are checked
before a request is made, and the site is escaped in the request path; long
values are clipped and the output is capped.

## Notes

- Add the service account as a user on each property; the only scope
  requested is `webmasters.readonly`.
- Search queries are aggregates across all searchers. Google holds back
  rare queries for privacy, so grouped rows may add up to less than the
  total.
- The newest data usually lags by a day or two, and Search Console keeps
  16 months of it.
