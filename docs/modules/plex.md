# Plex

Libraries, new arrivals and who's watching on your Plex Media Server.

**Setup.** Find your X-Plex-Token (Plex's support article "Finding an
authentication token", or the `X-Plex-Token` in the address when you view an
item's XML), store it in the vault and enter the server's address, such as
`http://plex.local:32400`.

| Action | Risk | Notes |
| --- | --- | --- |
| `libraries` | read | Id, title, type and whether a scan is running. |
| `recent` | read | Recently added, across all libraries or one (`library`), up to 100. |
| `sessions` | read | Who is watching what, on which device, progress, and whether the server is transcoding. |
| `refresh` | write | Scans a library for new and changed files. |
| `stop` | destructive | Ends a stream and shows the viewer `message`. The preview names the person, title and device. Needs Plex Pass on the server. |

Library ids must be numbers and session ids plain tokens, so input can't
change which address is called.
