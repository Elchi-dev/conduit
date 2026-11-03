# Twitch

See who's live, and change your own stream's title and category.

**Setup.** At dev.twitch.tv, Your Console, Applications, register an
application (any OAuth redirect, such as `http://localhost`), and copy its
client ID and a client secret. Store the secret in the vault. That's enough
for reading. To change your stream, also store a user access token with the
`channel:manage:broadcast` scope (for example from the Twitch CLI:
`twitch token -u -s channel:manage:broadcast`). Optionally list the channels
you check most.

| Action | Risk | Notes |
| --- | --- | --- |
| `streams` | read | Live or not, title, game, viewers and start time, for up to 100 channels |
| `channel` | read | A channel's title and category, live or not |
| `set_stream` | write | Your title and/or category (by name or id). Preview first; undo puts the previous ones back. Needs the user token |

**Security.** The app token is fetched with the client secret and kept in
memory until it expires. The user token can change your channel's title and
category, nothing else; Twitch tokens expire, so renew it when health says it
stopped working.
