# PhotoPrism

Your [PhotoPrism](https://www.photoprism.app) library: counts, the newest
photos, albums, and indexing new files. It uses PhotoPrism's REST API with an
app password.

**Setup.** In PhotoPrism open Settings → Account → Apps and Devices, create
an app password (scope it to what Conduit should do), and store it in the
vault. A token from `photoprism auth add` works too. Enter PhotoPrism's
address, such as `https://photos.example.com`. The password acts as that
user; indexing needs a user who may update the library.

| Action | Risk | Notes |
| --- | --- | --- |
| `library_stats` | read | Counts of photos, videos, live photos, albums, folders, months, favourites, private, archived, items to review, people, labels and files, and the version. Counts of places, states and countries are left out. |
| `recent_photos` | read | The newest photos (up to 100), optionally filtered with PhotoPrism's search (`label:cat year:2025`), with when they were taken, type, favourite and private. No places, coordinates, file names or captions. Search results don't say where a title came from, and PhotoPrism makes titles from places (`Berlin / 2025`), so a photo with a place keeps its title only when the title isn't in that `a / b` form and names none of the place's parts. The search takes only `label`, `year`, `month`, `day`, `before`, `after`, `favorite`, `type`, `video`, `photo` and `live` filters. It's read as PhotoPrism reads it (split on any Unicode space, quotes dropped, keys in any case) and sent rebuilt from the checked filters. Anything else is refused, since it can find photos by place: place filters (`near:`, `country:`, `lat:`), `keywords:`, `path:`, `title:` and the like, and free text, which matches keywords PhotoPrism makes from place names. Use `photo_places` for those. |
| `photo_places` | read, sensitive | The same listing with the full title, caption, place label, city, state, country and coordinates, with any PhotoPrism search. Kept out of the audit log, approvals and events. |
| `albums` | read | Albums or months (`type`), with photo counts. The `query` is words in the title; filters (`key:value`, which PhotoPrism would read as other album fields, such as `type:moment`) are refused. PhotoPrism's place-based albums (states, moments) aren't offered. Album titles are yours, so one you named after a place shows here. |
| `folders` | read, sensitive | Folders of originals with photo counts. Folder names often name places (`2026/Italy-trip`), so it's kept out of the audit log, approvals and events. Same `query` rule as `albums`. |
| `start_index` | write | With a preview. Indexes `originals` or a subfolder (`path`, such as `2026/11`), adding new and changed files; `rescan` re-reads every file. Cleanup isn't offered. PhotoPrism only answers when indexing is done, so after 20 seconds Conduit reports it as still running in the background, but only once the request has reached the server. There's no undo: indexing adds what's already in your originals. |

Creating share links isn't offered: a link anyone can open is publishing,
which Conduit treats as destructive, and the module doesn't do it at all.

**Security.** The app password goes in the `Authorization` header; the client
won't follow a redirect to another host or from https to http. Searches with Unicode control or format characters (newlines, zero-width
and direction marks) are refused. Index paths
are checked (plain folder names, no `..` or hidden folders) before they're
sent. For a self-signed certificate, pin its SHA-256 `fingerprint`.
