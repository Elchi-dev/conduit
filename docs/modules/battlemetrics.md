# BattleMetrics

Keep an eye on your game servers through
[BattleMetrics](https://www.battlemetrics.com): who's online, rank and status
for each server you run, the details of any public server, and how the player
count moved over the last hours or days. It's read-only.

**Setup.** On battlemetrics.com open Account, Developers and create a
personal access token (it only needs to read); store it in the vault. Add your
servers' BattleMetrics ids to `servers` (the number at the end of the
server's page address, such as `battlemetrics.com/servers/rust/1234567`), up
to 25. The health check reads each listed server and says how many are
online; with no servers listed it just checks the token.

| Action | Risk | Notes |
| --- | --- | --- |
| `servers` | read | Each listed server with status, players and maximum, rank, game, country and a link, busiest first, plus totals. A server that can't be read shows its error instead of failing the list. |
| `server` | read | Any public server by id: the same fields, when BattleMetrics last updated it, and game details such as map, mode and version. |
| `player_history` | read | Player count over the last `hours` (default 24, up to 720 = 30 days) with the low, high and average. Points are every 30 minutes up to two days, hourly up to a week and daily beyond. |

**Security.** The token goes in the `Authorization` header and the client
won't follow a redirect to another host. Server ids must be numbers before
they reach a request. Server addresses and IPs aren't returned, and game
details are cut down to plain one-line settings: a detail whose name
suggests an address, port, host, connect link, URL, RCON setting, password,
key or owner id is dropped, and so is any text value that contains an IP
address, a host:port or a connect link (a message of the day with the
connect string, for example). An address inside a server's name is shown as
`[address]`.

## Notes

- RCON, bans, player lists and organization features aren't included.
- BattleMetrics allows 60 requests a minute (300 with a token). A refused
  request waits once for the time BattleMetrics asks (up to 30 seconds) and
  is tried again.
- The server and player count history paths come from BattleMetrics'
  documentation as used by established clients; the official page could not
  be read in full when this module was written.
