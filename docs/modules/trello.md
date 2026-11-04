# Trello

Trello boards, lists and cards: search, see what's due soon, and add, move,
comment on, archive and unarchive cards.

**Setup.** Trello issues API keys to Power-Ups: open
[trello.com/power-ups/admin](https://trello.com/power-ups/admin), create (or
pick) a Power-Up, open its API key page and copy the key, then follow the
"Token" link there to generate a token for yourself. Store the token in the
vault; the key can be entered as is (it isn't a secret on its own) or as a
`secret://` reference. The token acts as you on every board you can see, so
keep writes on ask in your policies if an agent uses it.

| Action | Risk | Notes |
| --- | --- | --- |
| `boards` | read | Your open boards, with links and when they were last active. |
| `lists` | read | A board's open lists, in order. |
| `cards` | read | Open cards on a `board` or in a `list`, with list name, labels, due date and link. Up to `limit` (default 100). |
| `search` | read | Trello search over cards; its operators (`board:`, `list:`, `label:`, `due:week`, `is:open`) work. |
| `due_soon` | read | Unfinished, unarchived cards due within `days` (default 7) on one `board` or all your open boards, overdue ones first and marked `overdue`. |
| `card` | read | A card with its description, list, board and labels. |
| `add_card` | write | `list`, `name`, optional `description`, `due` (RFC 3339, or a date, which means noon UTC) and `position` (`top`, `bottom`, default bottom, or a number). The preview shows the card; undo archives it. |
| `move_card` | write | To any `list` you can see, on the same or another board, at `position` (default top). The preview shows from and to; undo moves it back to its old list and position. |
| `comment` | write | Comments as you; everyone on the board sees it. With a preview, no undo (delete it in Trello). |
| `archive_card` | write | Archiving closes a card but keeps it, so it's a write with undo (unarchive), not a destructive action. With a preview. |
| `unarchive_card` | write | Sends an archived card back to its list; undo archives it again. |

Boards and cards can be given as an id, an 8-character short link or a
`https://trello.com/b/…` or `/c/…` link; lists by id (see `lists`). Deleting
cards isn't part of this module.

**Security.** The key and token go in the `Authorization` header (Trello's
`OAuth oauth_consumer_key=…, oauth_token=…` form) rather than the query
string, so they stay out of access logs, and the client won't follow a
redirect to another host. Ids and short links are checked before they reach
a request path, and links are only accepted from `https://trello.com`.
