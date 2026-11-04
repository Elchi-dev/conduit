# Lichess

Your [Lichess](https://lichess.org) ratings, recent games at a glance and,
with a token, your ongoing games and whose turn it is. Works for any public
player too. It's read-only.

**Setup.** Enter your Lichess username, and that's enough for profiles and
games. For your ongoing games, create a personal access token at
[lichess.org/account/oauth/token](https://lichess.org/account/oauth/token)
and store it in the vault; with a token the username can be left empty.

| Action | Risk | Notes |
| --- | --- | --- |
| `profile` | read | Rating, games, progress, deviation and global rank per speed and variant (provisional ones marked), Puzzle Storm, Racer and Streak bests, game counts (win, loss, draw, playing), hours played, joined and last seen. Any `username`, or yours. |
| `games` | read | The latest `count` games (default 10, at most 50), newest first: opponent and rating, your rating and change, result and how it ended, speed, time control, opening and accuracy when analysed, plus a win/loss/draw tally. Filter with `days` (up to 365), `perfType` (`blitz`, `rapid`, `chess960`…) and `rated`. |
| `ongoing` | read | Your games in progress, most urgent first: opponent, your color, whether it's your turn and time left. Needs the token. |

**Security.** The token goes in the `Authorization` header and the client
won't follow a redirect to another host. Usernames and filters are checked
before any request. Games are requested without moves, PGN, clocks or
analysis; profile text (bio, real name, location, links) isn't read, and an
ongoing game's private id (which lets its holder play moves) is never
returned.

## Notes

- Lichess asks for one request at a time, so Conduit sends them one after
  another. After a "too many requests" answer it pauses for the time Lichess
  asks, or a full minute, and tries once more.
- Which token scopes `ongoing` needs isn't stated in the API reference this
  module was checked against; if Lichess refuses it, create the token with
  the scopes the token page suggests for reading games.
