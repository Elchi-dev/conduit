# YouTube

Your YouTube channel through the YouTube Data API v3: subscribers and
views, recent uploads with their views, whether you're live (with
concurrent viewers) and what's scheduled, the comments on your videos, and
changing a video's title and description.

**Setup.** In the [Google Cloud Console](https://console.cloud.google.com/),
create a project, enable the *YouTube Data API v3*, set up the OAuth
consent screen (External, Testing is enough; add yourself as a test user)
and create an OAuth client ID of type *Desktop app*. Store its client
secret in the vault. Then get a refresh token for the
`https://www.googleapis.com/auth/youtube.force-ssl` scope, signed in as the
account that owns the channel: the quickest way is the
[OAuth 2.0 Playground](https://developers.google.com/oauthplayground)
(gear icon, *Use your own OAuth credentials*, enter the client ID and
secret, authorize that scope, *Exchange authorization code for tokens*).
Store the refresh token in the vault and enter the client ID with both
references. While the consent screen is in Testing, Google expires refresh
tokens after seven days; publish the app (no review is needed for your own
account) to keep it.

| Action | Risk | Notes |
| --- | --- | --- |
| `channel` | read | Name, handle, subscribers (unless hidden), total views, video count, created. |
| `recent_videos` | read | Your latest uploads (`count`, 10, up to 50) with views, likes, comments, privacy and whether they're live or upcoming. |
| `live` | read | `live` true or false, the active broadcasts with concurrent viewers, and upcoming scheduled ones. |
| `update_video` | destructive | Sets a video's `title` (1–100 characters, one line) and/or `description` (up to 5000), seen by everyone who watches it. The preview shows the old and new text; undo puts the old ones back. Only videos on your own channel; tags, category and language are kept. |
| `comments` | read, sensitive | Recent comments on your videos, or one `videoId`, newest first: author, text, likes, replies. Sensitive because it names and quotes viewers. |

`update_video` is destructive because a title or description is public: an
agent approved for writes alone can't change what your audience sees.
Its preview and undo hold the old and new text and go into the audit log
as they are, so don't keep private notes in video descriptions you let an
agent edit.

**Security.** The client secret and refresh token are read from the vault
for each token refresh; the access token stays in memory until it expires.
The API address isn't a setting, and redirects to another host are
refused. YouTube gives each Cloud project 10,000 quota units a day: a list
costs 1, a video update 50; when it runs out the module says so.
