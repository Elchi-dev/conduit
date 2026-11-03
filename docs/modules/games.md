# Games

The local Steam library: what's installed, how big it is, launching, and
what's running. One instance per computer.

It reads Steam's own files (`libraryfolders.vdf` and the app manifests), so
it needs no account. The Steam folder is found automatically on Windows,
macOS and Linux (including the Flatpak); set `steamPath` otherwise. A Steam
Web API key and your 64-bit Steam id are optional and add play time and games
that aren't installed.

| Action | Risk | Notes |
| --- | --- | --- |
| `library` | read | Installed games across all library folders, with size and last update |
| `owned` | read | Owned games and hours played (needs the API key) |
| `running` | read | Games running now, found by their install folder |
| `launch` | write | Hands `steam://rungameid/<id>` to Steam |

| Event | When |
| --- | --- |
| `games.started` | a Steam game started (checked every 15 seconds) |
| `games.stopped` | it stopped |

Pair `games.started` with an automation that runs the computer's game mode,
pauses heavy containers or sets a "do not disturb" light; `games.stopped`
undoes it.
