# RomM

Your [RomM](https://romm.app) game library: platforms and how many games
each has, games by platform or search, and library scans.

**Setup.** Use a RomM user and store its password in the vault; an editor
or admin is needed to scan. Enter RomM's address, such as
`https://romm.example.com`. For a self-signed certificate, set
`fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `platforms` | read | Id, name, slug, number of games and a link to each platform. |
| `roms` | read | Games by name, on one `platform` (id) or all, optionally matching a `search`: file name, size, regions, languages, revision, when it was added and a link to open it. |
| `scan_library` | write | With a preview naming the platforms. Starts a scan of some `platforms` (ids) or all, in `quick` mode (new games) or `new_platforms` mode, fetching metadata from the sources set up in RomM. It runs in the background. |

**Security.** The login goes as HTTP basic auth, and the client won't follow
a redirect to another host or from https to http. Platform ids must be
numbers before they reach a request.

**Notes.** RomM starts scans over its live connection, as its web app does;
Conduit opens it over plain HTTP for the one request, so scanning needs
RomM 3 or later. Scan modes that rematch games you matched by hand aren't
offered.
