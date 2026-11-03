# Spotify

See what's playing and control playback on any of your Spotify devices.
Playback control needs Spotify Premium; without it, the module's health
says so and only reading works.

**Setup.**

1. At developer.spotify.com/dashboard, create an app. Add a redirect URI you
   control, for example `http://127.0.0.1:8888/callback` (nothing needs to
   run there).
2. Open this address in a browser, with your client id and redirect URI
   filled in:

   ```
   https://accounts.spotify.com/authorize?response_type=code&client_id=CLIENT_ID&redirect_uri=http%3A%2F%2F127.0.0.1%3A8888%2Fcallback&scope=user-read-playback-state%20user-modify-playback-state%20user-read-currently-playing
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

4. Store the client secret and the `refresh_token` from the answer in the
   vault, and enter the client id with both references in the module's
   settings.

Conduit exchanges the refresh token for short-lived access tokens itself and
keeps them only in memory.

| Action | Risk | Notes |
| --- | --- | --- |
| `now_playing` | read | Track, artists, album, progress, device, volume |
| `devices` | read | Device ids for the other actions |
| `play` | write | Resume, or play a `spotify:track:…`. Undo pauses. |
| `pause` | write | Undo resumes. |
| `next`, `previous` | write | |
| `volume` | write | 0 to 100. Undo restores the volume from before. |
| `queue` | write | Add a track to the queue |
| `search` | read | Tracks, with their URIs |

Every action takes an optional `device`; without it, the active device plays.

**Security.** The refresh token lets anyone with it control your playback
and see your listening, so it lives in the vault with the client secret.
The scopes above don't allow changing playlists or your library.

If Spotify hands out a new refresh token while refreshing (it rarely does for
this flow), Conduit uses it until the daemon restarts but can't write it back
to the vault. If health reports that the refresh token was revoked after a
restart, get a new one with the steps above and save it under the same name.
