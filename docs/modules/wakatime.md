# WakaTime

Coding activity from WakaTime, or from a self-hosted Wakapi server through
its WakaTime-compatible API: daily summaries, stats by language, project and
editor, and projects.

**Setup.** Copy your API key (WakaTime: Settings, API Key; Wakapi:
Settings, API Key) and store it in the vault. Leave the address empty for
WakaTime, or enter your Wakapi server's address, such as
`https://wakapi.example.com`; its compatible API
(`/api/compat/wakatime/v1`) is used. Another compatible server works with
its full API address. For a self-signed certificate, set `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `summaries` | read | Time coded each day between `start` and `end` (the last 7 days by default, up to a year), with the top five projects and languages per day, and the total. `project` limits it to one project. |
| `stats` | read | Total and daily average over `range` (`last_7_days`, `last_30_days`, `last_6_months`, `last_year`, `all_time`), the top languages, projects, editors and operating systems, and the best day. |
| `projects` | read | Projects with when they were last worked on. `query` filters by name. |

**Security.** The key goes in the `Authorization` header, and the client
won't follow a redirect to another host or from https to http. Dates and
ranges are checked before any request. Email addresses and repository
details aren't returned.

**Notes.** WakaTime calculates longer stats in the background: until
they're ready, `stats` says so and shows what it has. WakaTime's free plan
keeps two weeks of history.
