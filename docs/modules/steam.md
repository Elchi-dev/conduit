# Steam

Your Steam account online, through the Steam Web API: profile, friends and
what they're playing, recently played games, achievements and how many
people play a game. It's read-only.

The [Games](games.md) module is the library on this computer (play, stop,
play time) and can list owned Steam games with hours through the same key;
this module is the account and social side, and doesn't need Steam
installed.

**Setup.** Get a key at
[steamcommunity.com/dev/apikey](https://steamcommunity.com/dev/apikey) and
store it in the vault. Enter your 64-bit Steam id (17 digits starting with
7656119; it's in your profile's address, or look it up on steamid.io).
Friends, games and achievements are only readable when the profile's
privacy settings make them public; the health check says when the profile
is private.

| Action | Risk | Notes |
| --- | --- | --- |
| `profile` | read | Name, status, current game, country, Steam level, owned games count, created. |
| `friends` | read, sensitive | Friends with status and current game, playing first, then online. `onlineOnly` leaves the rest out. Sensitive because it names other people. |
| `recent` | read | Games played in the last two weeks with hours (`count`, default 10). |
| `owned_count` | read | How many games the account owns. |
| `achievements` | read | One game (`appId`): progress, the 20 latest unlocked, and what's left. |
| `player_count` | read | People playing a game (`appId`) on Steam right now. |

**Security.** The Steam Web API takes the key in the query string, so
redirects to another host are refused and errors never show a request
address. App ids must be positive numbers.
