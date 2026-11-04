# Xbox (OpenXBL)

Your Xbox Live account through [OpenXBL](https://xbl.io): profile, friends
and their presence, recent achievements and the games you've played. It's
read-only.

**Setup.** Sign in at xbl.io with your Xbox account, create an API key in your
profile and store it in the vault. The key reads the account it was made
with. OpenXBL's free plan allows about 150 requests an hour: `achievements`
across games makes up to five (the account, the games list and the three
most recent games with achievements), the others one or two.

| Action | Risk | Notes |
| --- | --- | --- |
| `profile` | read | Gamertag, gamerscore, tier, reputation, presence and the game being played. |
| `friends` | read, sensitive | Friends with presence text and gamerscore, online first; `onlineOnly` leaves the rest out. Sensitive because it names other people. |
| `achievements` | read | Latest unlocked (`count`, default 10) with game, gamerscore and rarity, from the last three games played, or one `titleId`. |
| `titles` | read | Games played, most recent first, with achievement and gamerscore progress (`count`, default 25). |

**Security.** The key travels in `X-Authorization`; the client refuses
redirects to another host (Go would otherwise forward that header). Title
ids must be numbers.
