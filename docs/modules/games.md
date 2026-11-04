# Games

Every game on this computer in one library, whichever launcher installed
it: press Play, see what's running, stop it, and keep a record of play time
that you and your agents can read. One instance per computer.

It reads each launcher's own local files, so it needs no accounts and no
logins. Nothing is sent anywhere except cover images, which are downloaded
once from the launcher's image server and kept.

## Launchers

| Launcher | Windows | macOS | Linux | Where it looks | How Play starts it |
| --- | --- | --- | --- | --- | --- |
| Steam | yes | yes | yes, also Flatpak and Snap; Proton games included | `steamapps/libraryfolders.vdf`, `appmanifest_*.acf`, play time from `userdata/*/config/localconfig.vdf` | `steam://rungameid/<id>` |
| Epic Games | yes | yes | through Heroic or Legendary | `%ProgramData%\Epic\EpicGamesLauncher\Data\Manifests\*.item` (macOS: `~/Library/Application Support/Epic/...`), covers from the launcher's `Catalog\catcache.bin`; Legendary's `installed.json` (plain or inside Heroic, also the Flatpak) | `com.epicgames.launcher://apps/<namespace>%3A<item>%3A<app>?action=launch&silent=true`; `heroic://launch?appName=…&runner=legendary`; `legendary launch <app>` |
| GOG | yes | yes | through Heroic | registry `HKLM\SOFTWARE\WOW6432Node\GOG.com\Games\*`; GOG Galaxy's `galaxy-2.0.db` for titles, portrait covers, play time and last played; Heroic's `gog_store/installed.json` | the game's own program (GOG games need no client); `goggalaxy://openGameView/<id>` when only Galaxy knows it; Heroic link on Linux |
| Riot Games | yes | yes | no | `%ProgramData%\Riot Games\RiotClientInstalls.json` and `Metadata\<product>.<patchline>\*.product_settings.yaml` (macOS: `/Users/Shared/Riot Games`) | `RiotClientServices --launch-product=<product> --launch-patchline=<patchline>` |
| Battle.net | yes | yes | no (run it in Lutris or Heroic) | `%ProgramData%\Battle.net\Agent\product.db` (protobuf; the module reads the uid, product code and install path); if that can't be read, Blizzard entries in the Windows list of installed programs | `battlenet://<code>` (`Pro`, `WoW`, `D3`, `Fen`, `WTCG`, …) |
| EA app | yes | no | no | EA entries in the list of installed programs and `HKLM\SOFTWARE\WOW6432Node\EA Games`; offer ids from each game's `__Installer\installerdata.xml` | `origin2://game/launch?offerIds=…`, else the game's program |
| Ubisoft Connect | yes | no | no | `HKLM\SOFTWARE\WOW6432Node\Ubisoft\Launcher\Installs\<id>`, titles from the `Uplay Install <id>` entries | `uplay://launch/<id>/0` |
| Xbox | yes | no | no | games the Xbox app installed into `<drive>:\XboxGames\*\Content\MicrosoftGame.config` | `msxbox://game/?productId=<store id>`, else the game's program |
| itch.io | yes | yes | yes | the itch app's `db/butler.db` (SQLite): caves, games, install locations, seconds played | `itch://caves/<cave>/launch` |
| Lutris | no | no | yes, also Flatpak | `~/.local/share/lutris/pga.db` (SQLite), covers from `coverart/` | `lutris:rungameid/<id>` |
| Other installed games | yes | no | no | the Windows list of installed programs (both registry views and the current user), for known game publishers (Rockstar, Bethesda, CD PROJEKT, Mojang, HoYoverse, …), skipping launchers, redistributables and anti-cheat | the program from the entry's icon |
| Added by you | yes | yes | yes | `add_custom` (a program), `add_link` (a launcher link) | the program with its arguments and working folder, or a launcher link |

**Not supported:** Microsoft Store apps that aren't Xbox games (listing
them needs the AppX APIs, which Conduit doesn't call); the EA app, Ubisoft
Connect and Xbox outside Windows; Battle.net and Riot on Linux except as
Wine games in Lutris or Heroic (they then show up there). `refresh` says
which launchers it found, which aren't available on this operating system,
and any file it couldn't read.

When two launchers list the same folder (a Steam game also in the
Windows list of installed programs, a Lutris game imported from Steam), the
first one in the table above owns it, so every game appears once.

## The game model

Every game has the same fields, whatever the launcher:

| Field | Meaning |
| --- | --- |
| `id` | `<launcher>:<native id>`, e.g. `steam:570`, `epic:Fortnite`, `gog:1207658924`, `riot:valorant`, `battlenet:pro`, `custom:minecraft` |
| `title`, `launcher`, `nativeId` | |
| `installed`, `installPath`, `sizeBytes`, `size` | |
| `executables`, `processNames` | when the launcher says (used to recognise the game running) |
| `hasCover`, `cover` | a portrait (2:3) cover: Steam's `library_600x900.jpg`, Epic's tall box art, GOG Galaxy's vertical cover, Heroic's box art, itch.io's cover, Lutris' cover art, or the link you gave |
| `lastPlayed` | the later of Conduit's record and the launcher's own |
| `playSeconds` | play time Conduit recorded |
| `launcherPlaySeconds` | play time the launcher recorded (Steam, GOG Galaxy, itch.io, Lutris) |
| `totalPlaySeconds` | the larger of the two |
| `running` | whether it's running now |
| `appId` | the Steam app id (Steam games), as before |

## Play tracking

While the daemon runs, the module looks at running processes every 10
seconds (gopsutil, no cgo, on all three systems). A process belongs to a
game when its program lies in the game's install folder (the deepest folder
wins) or is one of its listed programs. When Windows hides a process's
path (anti-cheat protected games), the program name the launcher lists is
used instead. On Linux, games under Wine and
Proton are recognised through the Windows path in their command line
(`Z:\…`), and Steam games through Steam's launch wrapper (`AppId=<id>`).
Games you add can name process names to watch for (a launcher script that
starts `java`, say). Folders too general to mean one game (`/usr`,
`C:\Program Files`, your home folder) are ignored.

Each run becomes a session (start, end, seconds). The module publishes
`games.started` when a game appears and `games.stopped` when it's gone, with
the session's length. Sessions in progress are saved every minute; if the
daemon stops while a game runs, the next start continues the same session
when the same process is still there, or closes it where it was last seen.

Data lives in `<data dir>/games/games.json` (sessions, open sessions, games
you added) and covers in `<data dir>/games/covers/`. Up to 50,000 sessions
are kept. Set `"track": false` to stop recording.

## Actions

| Action | Risk | Notes |
| --- | --- | --- |
| `library` | read | Every game. Filters: `launcher`, `installed`, `query` (words in the title), `sort` (`title`, `recent`, `played`, `size`), `limit` |
| `game` | read | One game (`id`) with its last 30 days of stats, its last 50 sessions, how it starts, and its processes when running |
| `stats` | read | Over the last `days` (default 30), optionally for one `gameId`: total, sessions, average and longest session, days played, play time per day (with a chart series) and per game, top five games, and the current and longest streak of days in a row (over all history; today or yesterday keeps a streak going). Days follow the computer's time zone; a session over midnight counts on both days |
| `running` | read | Games running now: processes (pid, name, program), since when, seconds |
| `play` | write | Starts a game (`id`) through its launcher link or its program. Refused when it's already running |
| `stop` | destructive, dry run | Asks the game's processes to close (SIGTERM; on Windows `taskkill` without `/F`, which sends a close message), waits `timeoutSeconds` (default 10, at most 120), then ends the rest (SIGKILL; `taskkill /F /T`). The preview names the game and each process with its pid. Only processes matched to that game are touched |
| `add_custom` | destructive, dry run, undoable | Adds a game: `title`, and a program (`executable`, `args`, `workingDir`) or a launcher link (`uri`), not both; optional `coverUrl` (https), `processNames`, `installPath`. The preview shows the full command line, the working folder and each argument. Undo removes it |
| `add_link` | write, undoable | Adds a game that starts through a launcher link (`title`, `uri`; optional `coverUrl`, `processNames`, `installPath`). It refuses `executable`, `args` and `workingDir`. Undo removes it |
| `remove_custom` | write, undoable | Removes a game you added; its play history stays. Undo adds it back with the same id |
| `refresh` | read | Looks at every launcher now (the library is otherwise cached for a minute) and reports each one: supported here, found, how many games, any error |
| `owned` | read | Owned Steam games and hours (needs a Steam Web API key and your Steam id) |
| `launch` | write | Starts a Steam game by `appId`. Kept for automations written before `play` |

`add_custom` registers a program the daemon will start on `play`, so it is
as powerful as running that command (like `servers.run`) and is rated
destructive: by default an agent's call waits for approval, which shows the
command line. A game with only a launcher link can be added with `add_link`
as a write.

Launch links are handed to the system (`rundll32 url.dll,FileProtocolHandler`
on Windows, `open` on macOS, `xdg-open` elsewhere), which passes them to
whatever handles the scheme. Some Windows handlers (`ms-msdt:`,
`search-ms:`, `ms-officecmd:` …) run code or open remote files, so only the
schemes the module itself generates are accepted, when adding a game and
again on `play`: `steam`, `heroic`, `com.epicgames.launcher`, `goggalaxy`,
`battlenet`, `origin2`, `uplay`, `msxbox`, `itch` and `lutris`.

| Event | When | Data |
| --- | --- | --- |
| `games.started` | a game started | `id`, `title`, `launcher`, `appId` (Steam), `pid`, `since` |
| `games.stopped` | it stopped | `id`, `title`, `launcher`, `appId`, `since`, `end`, `seconds` |

Pair `games.started` with an automation that turns on the computer's game
mode, pauses heavy containers or sets a "do not disturb" light;
`games.stopped` undoes it. An agent can answer "how much did I play this
week?" with `stats` and "what have I not touched in a month?" with `library`
sorted by `recent`.

## Settings

| Setting | Notes |
| --- | --- |
| `steamPath` | Steam's folder, when it isn't found by itself |
| `apiKey`, `steamId` | Optional, for `owned` |
| `disabledLaunchers` | Launchers not to look at, e.g. `["windows"]` |
| `track` | `false` to stop recording sessions |

## The library page

The module's page in the app (`web/src/modules/games/`, registered in
`web/src/modules/index.ts`) shows the library as a grid of 2:3 covers with
filter chips per launcher, search and sorting (recently played, most played,
A–Z). Play appears on hover or keyboard focus (always, on touch screens).
Games without cover art get a poster set from their title. A banner shows
what's playing now with a running clock. Each game opens a drawer with its
play time, a 30-day chart, its sessions, where it's installed and how it
starts, and Stop (with the preview) while it runs. "All actions" switches to
the plain action list.

Covers come through the daemon at `GET /api/v1/games/covers/{id}` (needs
`modules:games:read`), so the page never loads images from other sites:
from the launcher's local cache when there is one, else downloaded once over
https (JPEG, PNG, WebP, GIF or AVIF only, at most 8 MB) and kept. The
download uses its own client: no proxy, https only, at most 3 redirects
(each to https), and every connection is checked when it's made, so it can
only reach public addresses (not loopback, private, link-local,
carrier-grade NAT `100.64.0.0/10`, unique local, multicast, NAT64
`64:ff9b::/96` or their IPv4-mapped forms), whatever the name resolves to or
a redirect points at. The page refreshes when `games.started` or
`games.stopped` arrives.
