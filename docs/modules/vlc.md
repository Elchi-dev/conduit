# VLC

VLC media player through its web (Lua HTTP) interface: what's playing,
play and pause, next and previous, the volume and the playlist.

**Setup.** In VLC, *Tools*, *Preferences*, *Show settings: All*,
*Interface*, *Main interfaces*: tick **Web**; under *Main interfaces*,
*Lua*, set a **Lua HTTP password**. Restart VLC. Store the password in the
vault and enter the address (`http://127.0.0.1:8080` by default; `--http-host`
and `--http-port` change it). VLC only answers on localhost unless you
allow other addresses, and it speaks plain HTTP, so keep it on your own
machine or network.

| Action | Risk | Notes |
| --- | --- | --- |
| `status` | read | Playing, paused or stopped, title, position (seconds and percent), length, volume percent, shuffle, loop and repeat. |
| `now_playing` | read | Title, artist, album, genre, stream info or file name, with position and length. |
| `play` | write | Resumes, or starts the playlist. Undo pauses again when it was paused. |
| `pause` | write | Pauses. Undo resumes. |
| `next` | write | Next playlist item. Undo goes back. |
| `previous` | write | Previous playlist item. Undo skips forward again. |
| `set_volume` | write | `percent`, 0–200 (100 is normal). Undo restores the old volume. |
| `playlist` | read | The playlist's items (up to `limit`, 100) with length, marking the current one, and the total. |

Every write has a preview. File addresses are never returned: a network
share's can hold its password.

**Security.** The password is sent with HTTP basic authentication (VLC
uses no user name); redirects to another host or from https to http are
refused.
