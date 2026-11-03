# Jellyfin

Your media server: what's been added, who's watching what, library scans and
messages to viewers. Works with Emby too.

**Setup.** In Jellyfin, Dashboard, API Keys, add a key for Conduit and store
it in the vault. Enter the server's address, such as
`http://media.local:8096`.

| Action | Risk | Notes |
| --- | --- | --- |
| `libraries` | read | Name, kind and folders |
| `recent` | read | Newest movies, episodes, albums and books |
| `sessions` | read | Who's watching, on which device, what, paused or not, and how far in |
| `scan` | write | Look for new and changed files in every library |
| `message` | write | A short message on a viewer's screen |
| `stop` | destructive | Stop what a session is playing |

**Security.** An API key has full admin rights on the server; the module
only uses the calls above. Session ids are checked before they go into a
request path.
