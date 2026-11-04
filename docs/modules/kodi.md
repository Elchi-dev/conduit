# Kodi

Kodi through its JSON-RPC API over HTTP: what's playing, play/pause and
stop, the volume, library scans, notifications on the screen, and recently
added movies and episodes.

**Setup.** In Kodi, turn on Settings → Services → Control → *Allow remote
control via HTTP*, set a username (`kodi` by default) and password, and
note the port (8080). Store the password in the vault and enter the
address, such as `http://livingroom.local:8080`. Kodi's web server speaks
plain HTTP unless you set it up with a certificate, so keep it on your
network (or reach it through one of Conduit's networks).

| Action | Risk | Notes |
| --- | --- | --- |
| `players` | read | The active players with what they play (title, show and episode, artist, album), playing or paused, position, length and percent; and the volume and mute. |
| `play_pause` | write | Pauses or resumes a `player` (the active one by default); `play` true or false, or leave it out to toggle. Undo puts it back. |
| `stop` | write | Stops a player. No undo: playback ends (Kodi may offer to resume a library item next time it's played). |
| `set_volume` | write | Sets `volume` (0–100) and/or `muted`. Undo restores both. |
| `scan_library` | write | Scans the `video` (default) or `audio` sources for new items. |
| `notify` | write | Shows `title` and `message` on screen for `seconds` (5, 2–60). Control characters are refused. |
| `recent_movies` | read | Movies added most recently, with year, rating, length, genres, added and watched. Up to `limit` (100). |
| `recent_episodes` | read | Episodes added most recently, with show, season and episode, aired, added and watched. |

Every write has a preview. File paths are never requested, since paths to
network shares can contain their passwords.

**Security.** The password is sent with HTTP basic authentication; the
client won't follow a redirect to another host or from https to http.
Player ids are checked against the active players before they're used.
