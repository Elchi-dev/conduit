# SABnzbd

The Usenet download queue and its speed, history with failure reasons,
pausing and resuming, adding an NZB by URL, deleting jobs and the speed
limit, through SABnzbd's API.

**Setup.** In SABnzbd, open Config, General, Security and copy the API key
(not the NZB key, which can only add files); store it in the vault. Enter
SABnzbd's address, such as `http://nas.lan:8080`, with its URL base if it
has one (`http://nas.lan:8080/sabnzbd`). For a self-signed certificate, set
`fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `queue` | read | Whether the queue runs or is paused, speed, the speed limit, what's left, time left and free disk space, and up to `limit` jobs with id, name, status, progress, size, what's left, time left, category and priority. |
| `history` | read | Finished and failed jobs: id, name, status, failure reason, size, category, completion time, download time and folder. `failedOnly` shows only failures. |
| `pause` | destructive | Pauses the whole queue, or with `jobs` only those jobs. The preview shows what changes; undo resumes what it paused. |
| `resume` | write | Resumes the queue or the given jobs; undo pauses what it resumed. |
| `add_url` | write | Has SABnzbd fetch an NZB from an http(s) `url` and queue it, with an optional job `name`, `category` and `priority`. Undo deletes the new job. |
| `delete` | destructive | Removes jobs from the queue or entries from history (up to 50 ids, from either), and their files with `deleteFiles`. With a preview; no undo. |
| `set_speed_limit` | write | The download limit in KiB/s (`kiBs`, 0 = unlimited). Undo restores the previous limit. |

**Notes.** Job ids look like `SABnzbd_nzo_…`; `queue` and `history` list
them. A speed limit SABnzbd keeps as a percentage of the maximum line speed
is shown and restored as the KiB/s it works out to.

**Security.** The API key goes in the `apikey` query parameter, as SABnzbd
requires; the module adds it only when sending, so it never appears in
addresses shown in errors, and the client won't follow a redirect to
another host or from https to http. Job ids must match SABnzbd's format and
names and categories be one line before anything is sent. NZB URLs from
indexers usually carry the indexer's API key, so `add_url` is a sensitive
action: its input stays out of the audit log, previews and output show the
URL without its query, and history entries never include the NZB's
source URL. While SABnzbd fetches an NZB it names the job after the URL,
and a failed fetch goes to history under it: `queue`, `history` and
previews show such names without the URL's query (or anything after an `&`
in its path, where Newznab links carry the key), passed through the
redaction filter.
