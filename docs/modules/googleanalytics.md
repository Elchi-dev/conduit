# Google Analytics

Reports from Google Analytics 4: the properties a service account can see,
reports with your choice of dimensions, metrics and dates, and the users
active right now. The module is read-only.

**Setup.** In the Google Cloud Console, pick or create a project, turn on
the Google Analytics Data API and the Google Analytics Admin API, create a
service account and download a JSON key for it. Store the whole key file in
the vault and enter its `secret://` reference as `serviceAccount`. Then, in
Google Analytics, open Admin, Property access management for each property
the module may read, and add the service account's email (the key's
`client_email`) with the Viewer role.

| Action | Risk | Notes |
| --- | --- | --- |
| `properties` | read | Property id, name and type, with the account it belongs to. |
| `report` | read | Rows of up to 9 `dimensions` (such as `pagePath`, `country`, `sessionDefaultChannelGroup`, `date`) with up to 10 `metrics` (such as `activeUsers`, `sessions`, `screenPageViews`, `bounceRate`; these three by default), sorted by the first metric. Covers the last `days` (28 by default, today included) or a `from`/`to` range of up to a year. Up to `limit` rows (100 by default, at most 1000), with GA's total `rowCount`. |
| `realtime` | read | Active users in the last 30 minutes, optionally by realtime dimensions such as `country`, `deviceCategory` or `unifiedScreenName`. |

Names are GA4 API names, as listed in Google's Data API schema; custom
dimensions and metrics work as `customEvent:name`, and key events as
`keyEvents:name`.

**Security.** The service account signs a JWT with its key and exchanges it
at Google's token endpoint for a read-only access token, kept in memory
until shortly before it expires; the key file's own `token_uri` is never
used. Calls go only to Google's API hosts, and the client won't follow a
redirect to another host. Property ids, names, dates and limits are checked
before a request is made; long values are clipped and the output is capped.

## Notes

- Grant the service account the **Viewer** role on each property; the only
  scope requested is `analytics.readonly`.
- User-scoped custom dimensions (`customUser:…`) and identifiers such as
  `userId` are refused, so reports stay about traffic, not people.
- GA4 applies its own quotas per property; a used-up quota is reported as
  such.
