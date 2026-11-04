# NZBGet

The [NZBGet](https://nzbget.com) Usenet downloader: the queue and its speed,
history with failures, pausing and resuming, deleting jobs and the speed
limit.

**Setup.** In NZBGet, open Settings, Security, and note `ControlUsername`
(`nzbget` by default) and `ControlPassword`; store the password in the
vault. Enter NZBGet's address, such as `http://nas.lan:6789`. For a
self-signed certificate, set `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `queue` | read | Whether downloads run, speed, speed limit, what's left, free disk space, and the jobs with status, progress, size, category and priority. |
| `history` | read | Finished and failed jobs with status (such as `success/all` or `failure/par`), kind, size, category, completion time, download time and folder. `failedOnly` filters. |
| `pause` | destructive | With a preview. Pauses all downloading, or with `jobs` (ids) only those jobs. "Nothing to change" when they're already paused. Undo resumes what it paused. |
| `resume` | write | With a preview. Resumes all downloading, or only `jobs`. Undo pauses them again. |
| `delete` | destructive | With a preview listing each job's size and what's left. Removes `jobs` from the queue; they go to history as deleted. |
| `set_speed_limit` | write | With a preview. Sets the limit in KiB/s (`0` for unlimited). Undo restores the previous limit. |

**Security.** The login goes as HTTP basic auth, and the client won't follow
a redirect to another host or from https to http. Job ids must be numbers
before they reach a request. The URL of a job added by URL isn't read
(indexers put their API key in it), and names and folders that hold a URL
lose its query.

**Notes.** Pausing and deleting single jobs uses the `editqueue` form of
NZBGet 18 and later. Whether `delete` also removes what a job downloaded
follows NZBGet's `DeleteCleanupDisk` setting.
