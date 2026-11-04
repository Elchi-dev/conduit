# Overseerr / Jellyseerr

[Overseerr](https://overseerr.dev) or
[Jellyseerr](https://github.com/Fallenbagel/jellyseerr), which share an
API: media requests, approving and declining them, searching, and
requesting movies and shows.

**Setup.** Open Settings → General, copy the API key and store it in the
vault. Enter the address, such as `http://overseerr.local:5055`. The key
acts as the admin user.

| Action | Risk | Notes |
| --- | --- | --- |
| `requests` | read, sensitive | Requests, newest first, with `filter` (`pending` by default, `approved`, `processing`, `available`, `unavailable`, `failed`, `all`) and `limit` (up to 100): id, title and year (looked up for the first 25), movie or show, seasons, 4K, request and media status, who asked and when, who approved or declined; with counts by status. |
| `request` | read, sensitive | One request by `id`. |
| `approve` | destructive | Approves a pending request, which sends it to Radarr or Sonarr to download. It can't be taken back (declining afterwards doesn't remove it from Radarr or Sonarr, and the download uses disk and bandwidth), so it has no undo and is destructive, like other approvals in Conduit. |
| `decline` | write | Declines a pending request. It's a write rather than destructive because nothing is deleted and the person can simply request it again. It has no undo because the API can't put a request back to pending (approving it instead would start a download nobody asked for). |
| `search` | read | Movies and shows matching `query` (people are left out): TMDB id, type, title, year, a short overview, and whether it's available, requested or not. |
| `create_request` | destructive | Requests a `movie` or `tv` show by `tmdbId` (from `search`); for shows `seasons` is `"all"` (the default) or season numbers; `is4k` for the 4K server. The plan names the title. It's destructive like `approve`: the key acts as the admin, whose requests are approved at once and sent to Radarr or Sonarr to download. Undo deletes the request, but a download already started stays. |
| `delete_request` | destructive | Deletes a request (the undo of `create_request`). Anything Radarr or Sonarr already downloaded stays. |

`requests` and `request` are sensitive because they name the people who
asked; emails and Plex or Jellyfin usernames are never read out. The write
actions' plans and outputs carry only the id, title and status.

**Security.** The key goes in the `X-Api-Key` header; the client won't
follow a redirect to another host or from https to http. Ids, TMDB ids and
season numbers must be positive numbers, filters and media types come from
fixed lists, and the search text is percent-encoded the way Overseerr's
validator expects.
