# Bazarr

[Bazarr](https://www.bazarr.media) subtitles for your Sonarr series and
Radarr movies: what's missing, what was downloaded, throttled providers,
and searching for missing subtitles.

**Setup.** In Bazarr, open Settings, General, Security, copy the API key and
store it in the vault. Enter Bazarr's address, such as
`http://nas.lan:6767`, with its URL base if it has one (for example
`/bazarr`). For a self-signed certificate, set `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `status` | read | Bazarr's version, the Sonarr and Radarr versions it talks to, how many episodes and movies miss subtitles, throttled providers and health issues. |
| `wanted` | read | Episodes (`kind` `series`) or movies (`movies`) missing subtitles, with the languages missing (forced and hearing impaired marked). |
| `history` | read | Recent subtitle downloads, upgrades, uploads, syncs and deletions for `series` or `movies`: when, language, provider and score. |
| `providers` | read | Providers Bazarr paused after errors, with the reason and when it tries again. |
| `tasks` | read | Scheduled tasks with their interval, next run and whether each runs now. |
| `search_missing` | write | With a preview. Starts Bazarr's search for every missing subtitle of `series` or `movies` now; it downloads what it finds. "Nothing to change" when the search already runs. |
| `reset_providers` | write | With a preview listing the throttled providers. Lets Bazarr use them again right away. "Nothing to change" when none is throttled. |

**Security.** The API key goes in the `X-API-KEY` header, and the client
won't follow a redirect to another host or from https to http. `kind` must
be `series` or `movies` before anything reaches a request.

**Notes.** `search_missing` runs only Bazarr's own missing-subtitle search
tasks; other tasks aren't started from Conduit.
