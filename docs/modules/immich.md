# Immich

Your Immich photo and video server: library size, storage, users,
background jobs, recent uploads and albums.

**Setup.** In Immich, Account settings, API keys, add a key and store it in
the vault. An administrator's key also reads statistics, users and jobs and
can start jobs; any user's key reads storage, recent uploads and albums.
Enter the server address, such as `https://photos.example.com`.

| Action | Risk | Notes |
| --- | --- | --- |
| `server` | read | Version, and photos, videos and space used (admin). |
| `storage` | read | Size, used and free space of the library volume. |
| `users` | read | How many users, admins and active users, with each one's photos, videos, usage and quota (admin). Email addresses are left out. |
| `jobs` | read | Each job queue: running, paused, active, waiting, delayed and failed counts (admin). |
| `start_job` | write | Starts one of Immich's own jobs (thumbnails, metadata, video conversion, faces, smart search, duplicates, library scan, sidecars, storage template, migration, database backup) for the assets that need it, or for every asset with `force`. The preview shows the queue now. |
| `recent_assets` | read | Newest photos and videos: file name, type, date taken, owner, camera, city and country, size. No image data or GPS coordinates. |
| `albums` | read | Albums with size, owner, date range and whether they're shared. |

**Security.** The key travels in `x-api-key`; the client refuses redirects to
another host. Job names are checked against the list above before they go
into a request path.
