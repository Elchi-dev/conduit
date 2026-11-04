# FreshRSS

Unread counts and items in your [FreshRSS](https://freshrss.org) reader, your
subscriptions, and marking items read or unread, through FreshRSS's Google
Reader compatible API.

**Setup.** In FreshRSS, an administrator turns on the API under
Administration, Authentication ("Allow API access"). Then, in Settings,
Profile, set an **API password** (it's separate from your login password and
only works for the API) and store it in the vault. Enter FreshRSS's address,
such as `https://rss.example.com` (the folder where `api/greader.php` is; the
full `…/api/greader.php` address works too) and your user name.

| Action | Risk | Notes |
| --- | --- | --- |
| `unread_count` | read | Unread items in all, and per feed with its title, most first. |
| `unread` | read | Unread items, newest first, everywhere or in one `feed` (`feed/12`, see `subscriptions`): title, link, feed, author and date. |
| `subscriptions` | read | The feeds you follow with their categories, feed and site addresses. |
| `mark_read` | write | Marks up to 50 `items` (ids from `unread`) read. FreshRSS is asked for the items first, so the preview names them, items already read are left out, and undo marks only the changed ones unread. |
| `mark_unread` | write | The reverse, with the reverse undo. |

Listings return titles, links and dates, not article content.

**Security.** The API password is sent only to sign in (`ClientLogin`, in
the request body, never in the address); the session token it returns is
kept in memory, renewed once when FreshRSS rejects it, and never shown. The
client won't follow a redirect to another host, so a redirect can't replay
the password elsewhere. Feed and item ids are checked before they reach a
request. For a self-signed certificate, pin its SHA-256 `fingerprint`.
