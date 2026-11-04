# Sonarr, Radarr and the *arrs

One module for the *arr suite: Sonarr (TV), Radarr (movies), Lidarr
(music), Readarr (books) and Prowlarr (indexers). Each instance is one app;
add an instance per app. The `app` setting picks the API (v3 for Sonarr and
Radarr, v1 for the others) and what a library item is (series, movie,
artist, author).

**Setup.** In the app, open Settings, General, Security, copy the API key and
store it in the vault. The key has full control of the app. Enter the app's
address with its URL base if it has one, such as `http://nas.lan:8989` or
`https://media.example.com/sonarr`. For a self-signed certificate, set
`fingerprint` (SHA-256) rather than `insecureSkipVerify`. Health says when
the server is a different app than the one the instance is set up for.

| Action | Risk | Notes |
| --- | --- | --- |
| `status` | read | Version, branch, start time, OS, Docker, and the app's own health checks (warnings and errors, with wiki links). |
| `queue` | read | Downloads with progress (%), size and size left, time left, ETA, client, protocol, indexer, the episode, movie, album or book, errors and warnings. |
| `calendar` | read | What comes out in the next `days` (default 7; `pastDays` looks back), sorted by date. Radarr shows cinema, digital and physical release dates. |
| `wanted` | read | Monitored items that are out but missing. On Radarr before v5 (no wanted API) it's worked out from the movie list. |
| `library` | read | Library items whose name contains `query`, with episode, track or book counts, size on disk and status. The list is streamed, so large libraries are fine. |
| `lookup` | read | Searches the metadata source (TheTVDB, TMDb, MusicBrainz, Goodreads) for `term`, marks what's already in the library and gives the id to `add` with. |
| `add` | write | Adds a lookup result by `id` (TVDB id, TMDb id, MusicBrainz artist id, or foreign author id with its `term` for Readarr). Quality profile, root folder and (Lidarr, Readarr) metadata profile default to the first; pick them by name or id. Monitored, and searched for right away unless `search` is false. Sonarr monitors every season except specials. The preview names the profile and folder. Undo removes it again, keeping files; a download it started keeps going in the client. |
| `remove` | destructive | Removes a library item by `id`, keeping files unless `deleteFiles`. No import list exclusion is added. With a preview. |
| `search` | write | Searches the indexers for one library item (`id`), or for everything missing. A search can't be taken back, so there's no undo. |
| `history` | read | Recent grabs, imports, failures and deletions (Prowlarr: queries and grabs, with success). |
| `indexers` | read | Indexers with protocol, priority, whether they're enabled, and failures and back-off from the indexer status. |
| `test_indexers` | read | Tests one indexer (`id`) or all, and lists each one's validation failures. |

`queue`, `calendar`, `wanted`, `library`, `lookup`, `add`, `remove` and
`search` don't apply to Prowlarr and are refused before any request is made.

**Security.** The key goes in the `X-Api-Key` header, and the client won't
follow a redirect to another host or from https to http (Go would forward
that header). Library and indexer ids must be positive whole numbers before
they reach a request path; lookup ids are checked against the app's id
format. Indexer settings (their `fields`, which hold indexer API keys and
passwords) and history `data` beyond the indexer, client and message
(download URLs carry indexer keys) are never passed on.
