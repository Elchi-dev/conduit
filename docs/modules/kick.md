# Kick

Kick channels and who's live, through Kick's public API; with a user token
for your own channel, change your stream's title and category and post in
your chat.

**Setup.** At kick.com, Settings, Developer, create an app (redirect URL
such as `http://localhost`), copy its client ID and store the client secret
in the vault. That's enough for reading channels and livestreams (an app
token is fetched with the secret). To change your stream and chat, also
store a user **refresh token** with the scopes `user:read channel:read
channel:write chat:write`: authorize your app at
`https://id.kick.com/oauth/authorize` (OAuth 2.1 with PKCE) and exchange
the code at `https://id.kick.com/oauth/token`. Kick rotates refresh tokens:
the new one is written back to the vault each time. Optionally list the
channels you check most.

| Action | Risk | Notes |
| --- | --- | --- |
| `channel` | read | A channel's title, category, description, live and viewers (yours by default with the user token, or the first listed channel); subscribers for your own. |
| `livestreams` | read | Live or not, title, category, viewers, start time and language for up to 50 channels. |
| `set_stream` | destructive | Your stream `title` (one line, up to 140) and/or category, by `category` name (an exact match; close ones are suggested) or `categoryId`. Preview first; undo puts the previous ones back. |
| `send_chat` | destructive | Posts `message` (one line, up to 500) in your own channel's chat. The preview quotes it. |

Changing the title or category and chatting are seen by your viewers, so
both are destructive: an agent approved for writes alone can't reach your
audience. Messages only go to the channel the user token belongs to.

**Security.** The API returns your stream key with your own channel; the
module never reads it into its output. The API address isn't a setting,
redirects to another host are refused, and token errors are redacted.
