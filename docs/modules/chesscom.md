# Chess.com

Profiles, ratings and win/loss records on [Chess.com](https://www.chess.com)
for you or any player, and a summary of any month's games, through
Chess.com's public data API. No account or key needed, and it's read-only.

**Setup.** Enter your Chess.com username; actions use it when they name no
player.

| Action | Risk | Notes |
| --- | --- | --- |
| `profile` | read | Username, title, membership, league, country, followers, streamer and verified flags, joined and last online. |
| `stats` | read | Current and best rating with wins, losses and draws for each time control (`daily`, `rapid`, `blitz`, `bullet`, `960_daily`), highest puzzle rating, best Puzzle Rush score and FIDE rating when set. |
| `archives` | read | The months that have games, newest first (`count`, default 24, at most 120). |
| `month` | read | One `month` (`YYYY-MM`, default this month, from 2007-01): games per time control with wins, losses, draws and rating change, and the latest `count` games (default 10, at most 50) with opponent, ratings, result, how it ended, accuracy and a link. |

**Security.** Usernames and months are checked before any request, and the
client won't follow a redirect to another host. Requests carry a
`User-Agent` naming Conduit, as Chess.com asks. Games are summarised: no
moves or PGN, and no real names, locations or avatars.

## Notes

- Chess.com serves one request at a time without limits, so Conduit never
  sends them in parallel. A "too many requests" answer is retried once after
  the wait Chess.com asks for (up to 30 seconds).
- Chess.com updates its public data periodically, so the latest game or
  rating can lag a little behind the site.
