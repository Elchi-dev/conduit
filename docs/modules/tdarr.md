# Tdarr

The [Tdarr](https://tdarr.io) transcoding server: its nodes and workers,
libraries with their statistics (files, transcodes, space saved), the queue
counts, and pausing and resuming a node.

**Setup.** Enter the Tdarr server's address, such as `http://nas.lan:8265`.
When authentication is on, create an API key in Tdarr under Tools, API Keys
and store it in the vault; without authentication, leave `apiKey` empty. For
a self-signed certificate, set `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `nodes` | read | Each node with its id, name, whether it's paused, version and worker limits, and its running workers with job type, status, progress, frames per second, time left and the file's name. |
| `libraries` | read | Each library with its id, name, whether it's processed and watched, priority and type, and its files, transcodes, health checks and space saved (GB); with the totals for all libraries. |
| `queue` | read | Files waiting for, done with and failed in transcoding and health checks, and the space saved (GB). |
| `pause_node` | destructive | With a preview. Pauses a `node` (its id or name): its workers take no new work. "Nothing to change" when it's already paused. Undo resumes it. |
| `resume_node` | write | With a preview. Resumes a paused `node`. Undo pauses it again. |

After a pause or resume the node is read back, and the action reports an
error if Tdarr kept it as it was.

**Security.** The API key goes in the `x-api-key` header, and the client
won't follow a redirect to another host or from https to http. A node is
checked before any request and then looked up among Tdarr's nodes, so only
an id Tdarr listed is sent. Workers show only the file's name, never its
folder, and the library, cache and output folders aren't read. Folders and
file paths are taken out of Tdarr's error messages, and names are shortened;
at most 50 nodes (and 50 workers each) and 200 libraries are listed.

**Notes.** Queue counts follow the tables in Tdarr's own interface, which
leave out disabled libraries. Library statistics are read for the first 25
libraries. Built against the API used by Tdarr's own plugins and dashboard
integrations; pausing every node at once (a global setting) isn't offered.
