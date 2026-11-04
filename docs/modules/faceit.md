# FACEIT

Look up FACEIT players by nickname and see their skill level, Elo and region
per game, lifetime stats and recent matches with results, through the
[FACEIT Data API](https://docs.faceit.com/docs/data-api/data/). It's
read-only.

**Setup.** Sign in to the [FACEIT Developer Portal](https://developers.faceit.com),
create an app in App Studio and add a **server-side** API key; store it in
the vault. Enter your FACEIT nickname (actions use it when they name no
player, and the health check shows your level) and your main game id
(`cs2` by default; others include `csgo` and `dota2`).

| Action | Risk | Notes |
| --- | --- | --- |
| `player` | read | Player id, nickname, country and, per game, skill level, Elo, region and in-game name. Give `nickname` or `playerId`, or neither for yours. |
| `stats` | read | Lifetime stats in `game` as FACEIT reports them, such as matches, win rate, K/D, headshots, streaks and recent results, with the current level and Elo. |
| `matches` | read | Up to `count` (default 10, at most 50) matches from the last `days` (default 30, at most 90), newest first: mode, competition, region, team names, score, the player's team and win or loss, with a tally. |

**Security.** The key goes in the `Authorization` header and the client
won't follow a redirect to another host. Nicknames, player ids and game ids
are checked before any request. Only stats and summaries come back: no
avatars, platform ids, friends, settings or chat.

## Notes

- Stat names differ per game and come straight from FACEIT, so they may
  change; nested per-map segments are left out. At most 40 stats are passed
  on: a name must be one line of up to 64 bytes, a value a number, true or
  false, or text of up to 64 bytes made one line, and a list keeps its
  first 10 such values; nested objects are dropped.
- A refused request (HTTP 429) waits once for the time FACEIT asks (up to 30
  seconds) and is tried again.
