# Spotify

Lets an agent know what you listen to and play anything on your devices:
what's playing, what you played (with times), your top tracks and artists,
liked songs, saved albums, playlists, search, the queue and devices; a
listening history that Conduit keeps itself, with stats; and playback,
playlists and library changes.

## Two ways to control playback

| Mode | Needs | Can do |
| --- | --- | --- |
| **Web API** | Spotify Premium | Everything, on any of your devices |
| **The Spotify app on this computer** | The desktop app running on the machine the daemon runs on: Linux (MPRIS over D-Bus) or macOS (AppleScript) | Play any track, album, playlist, artist or episode; pause, resume, next, previous, seek, shuffle; volume on macOS |

`playback` in the settings picks:

- `auto` (default): the Web API; when Spotify answers that the account
  isn't Premium (`PREMIUM_REQUIRED`), Conduit switches to the app on this
  computer and stays with it. Reading still uses the Web API.
- `web`: only the Web API.
- `local`: always the app on this computer.

Windows isn't supported for the app: media keys can't be aimed at Spotify
reliably, so Conduit doesn't pretend. Health says which mode is active
("playback through the Web API", or "through the Spotify app on this
computer (MPRIS)").

On macOS the first command makes the system ask whether Conduit may control
Spotify; allow it (System Settings, Privacy & Security, Automation). On
Linux the daemon must run as your user inside your desktop session, since it
talks to Spotify over the session's D-Bus.

Without any Web API credentials the module works with the app alone:
now playing and playback, no library, history or search.

## Setup: your own Spotify app

Each person registers their own app with Spotify; Conduit has no shared
client id. A personal app in development mode is enough.

1. At developer.spotify.com/dashboard, create an app (Web API). Add the
   redirect URI `http://127.0.0.1:8888/callback` (nothing needs to run there;
   Spotify requires `127.0.0.1` rather than `localhost`).
2. In Conduit, add the module with the client id; store the client secret in
   the vault. Run **Authorize link** (`auth_url`), or open this address with
   your client id filled in:

   ```
   https://accounts.spotify.com/authorize?response_type=code&client_id=CLIENT_ID&redirect_uri=http%3A%2F%2F127.0.0.1%3A8888%2Fcallback&scope=user-read-playback-state%20user-modify-playback-state%20user-read-currently-playing%20user-read-recently-played%20user-top-read%20user-library-read%20user-library-modify%20playlist-read-private%20playlist-read-collaborative%20playlist-modify-public%20playlist-modify-private
   ```

   Approve, and copy the `code` from the address the browser is sent to (the
   page itself may fail to load; that's fine).
3. Exchange the code for a refresh token:

   ```sh
   curl -s -u CLIENT_ID:CLIENT_SECRET \
     -d grant_type=authorization_code -d code=CODE \
     -d redirect_uri=http://127.0.0.1:8888/callback \
     https://accounts.spotify.com/api/token
   ```

4. Store the `refresh_token` from the answer in the vault and enter its
   reference in the settings.

**Development mode limits.** Since February 2026 Spotify only runs a
development-mode app while its owner has Premium, and allows 5 users per
app (add them under the app's User Management). Someone without Premium
can't run an app of their own, but can be added as a user of a Premium
household member's app; reading then works on their free account, and
playback goes through the app on their computer.

**Scopes.** The link asks for everything the module uses:
`user-read-playback-state`, `user-modify-playback-state`,
`user-read-currently-playing`, `user-read-recently-played`,
`user-top-read`, `user-library-read`, `user-library-modify`,
`playlist-read-private`, `playlist-read-collaborative`,
`playlist-modify-public`, `playlist-modify-private`. If your refresh token
is from the older, playback-only link, Health lists what's missing; get a
new token with the link above.

**Tokens.** The client secret and refresh token live only in the vault.
Conduit trades the refresh token for short-lived access tokens, keeps those
in memory, refreshes them a minute before they expire, and once more if
Spotify rejects one early. If Spotify hands out a new refresh token, Conduit
writes it back to the vault under the same reference when the daemon allows
modules to (otherwise it uses it until the next restart and logs that).

## Reading

| Action | Notes |
| --- | --- |
| `now_playing` | Track or episode, artists, album, progress, device, volume, shuffle, repeat, and the album or playlist it plays from |
| `recently_played` | The last plays with the time of each (Spotify keeps 50) |
| `top_tracks`, `top_artists` | `range`: `short` (about 4 weeks), `medium` (about 6 months), `long` (about a year) |
| `saved_tracks`, `saved_albums` | Liked songs and saved albums, with when they were added |
| `playlists` | Your playlists, own and followed |
| `playlist_tracks` | A playlist's tracks with positions. Spotify only lists the tracks of playlists you own or collaborate on. |
| `search` | `types`: track, album, artist, playlist, show, episode. Spotify returns at most 10 per page; use `offset` for more. |
| `track`, `album`, `artist` | Details; an album with its track list, an artist with genres and albums |
| `queue`, `devices` | What plays next; device ids for the other actions |
| `history` | The local log, newest first, filtered by `since`, `until`, `artist` |
| `listening_stats` | For the last `days` (7): plays, minutes per day, top artists, tracks and albums, busiest hour |
| `auth_url` | The authorize link with every scope |

Everything takes Spotify URIs (`spotify:track:…`) or the links Spotify's
Share menu copies (`https://open.spotify.com/track/…`).

## Listening history

Spotify only remembers your last 50 plays. With **Keep a listening history**
on (the default once the Web API is set up), Conduit collects them every
`historyMinutes` (10) into a log in its data folder
(`modules/spotify/<instance>.history.jsonl`), so `history` and
`listening_stats` reach back as far as the log does. `history` and
`listening_stats` collect first, so they are current.

Minutes listened are an estimate: a track counts for its length, or for the
time until the next play when that came sooner (a skip). Spotify only
reports plays of 30 seconds or more. Days follow `timezone` (an IANA name)
or the daemon's.

Collect at least every hour or so if you listen a lot: more than 50 plays
between two collections are lost, as Spotify doesn't keep them.

## Playback and changes

| Action | Undo | Notes |
| --- | --- | --- |
| `play` | Back to what played before, or pause | `uri` (track, album, playlist, artist, show, episode), `uris` (several tracks), or `query` (+ `type`) to play the top search result; `startAt` a track within an album or playlist; `positionMs`; `device`. The preview names what will play where. |
| `pause`, `resume` | Each other | |
| `next`, `previous` | | |
| `seek` | Jump back | `positionMs` or `seconds` |
| `volume` | The volume before | 0 to 100 |
| `shuffle`, `repeat` | The setting before | repeat: `off`, `track`, `context` |
| `add_to_queue` | | Web API only (the app can't) |
| `transfer` | Back to the device before | Continue on another device |
| `create_playlist` | Deletes it | Private unless `public`; optional `uris` |
| `playlist_add` | Takes them out again, leaving tracks that were already there in place | `position` (0 is the top); empty appends |
| `playlist_remove` | Puts them back where they were | Removes every occurrence of each track |
| `playlist_reorder` | Moves them back | `rangeStart`, `insertBefore`, `rangeLength` (0-based, like Spotify) |
| `save`, `unsave` | The opposite, only for what changed | Tracks, albums, episodes, shows, artists (follow) and playlists (follow), up to 40 |

All of these are `write`. Playback actions take an optional `device`;
without it the active device plays. Playlist and library changes don't need
Premium.

**Security.** The refresh token lets anyone with it control your playback,
see your listening and change your playlists and library, so it lives in the
vault with the client secret. The listening log holds what you played and
when; it stays in the daemon's data folder on this machine.
