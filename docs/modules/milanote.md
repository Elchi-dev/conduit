# Milanote

Your Milanote boards: read them as structured data or Markdown, search them,
add notes, to-do lists and links, tick tasks, edit and move cards, move them
to the trash and back, and export a board as Markdown.

> **Unofficial.** Milanote has no public API. This module signs in like your
> browser does and talks to Milanote's private web API: the same JSON
> requests and live connection the web app uses. Milanote can change those at
> any time, and then the module stops working until it is updated. Health
> then says *"Milanote changed its web app — the module needs an update"*.
> The wire format is pinned in `modules/milanote/client.go` (`WireVersion`,
> currently 2026-10-18). **Check Milanote's
> [terms of service](https://milanote.com/legal/terms-of-service) before
> you turn it on.** Use it only for your own account and your own boards.

## Setup

Pick one way to sign in. You can also set both. The module then uses the
cookie first and falls back to the password when Milanote signs the cookie
out.

### Email and password

For accounts that sign in with an email and password. Store the password in
the vault and enter its `secret://` reference, along with your email.

The web app's sign-in form attaches an invisible Google reCAPTCHA token.
Conduit can't make one, so it sends none. Milanote may accept that, or it
may refuse the sign-in. Health then says *"sign-in failed: Milanote asked
for a browser check"*, and you should use a session cookie instead. Conduit
never tries to solve or get around a CAPTCHA or a firewall check.

### Session cookie (Google or Apple sign-in, or when the password is refused)

Accounts that use **Sign in with Google** or **Sign in with Apple** have no
Milanote password, so give Conduit the session cookie of a browser that is
signed in:

1. Sign in at [app.milanote.com](https://app.milanote.com) in Chrome, Edge,
   Firefox or Safari.
2. Open the developer tools (F12, or Cmd-Option-I on a Mac).
3. Chrome/Edge: **Application** tab → **Storage** → **Cookies** →
   `https://app.milanote.com`. Firefox: **Storage** tab → **Cookies**.
   Safari: **Storage** tab → **Cookies** (turn on *Show features for web
   developers* in Settings → Advanced first).
4. Find **`__Secure-milanote.session_token`** and copy its **Value**.
5. Store that value in the vault and enter its `secret://` reference as the
   **session cookie**.

You can also paste a whole `Cookie:` header copied from a request in the
**Network** tab (`name=value; name2=value2`). The module keeps the cookies
it needs.

The cookie lasts about a month. When Milanote signs it out, Health says
*"the session cookie has expired"*. Copy a fresh one. Signing out in that browser
usually ends the session too, so close the tab instead.

If your account asks for a second sign-in step, Conduit can't complete it;
use the session cookie.

**Optional:** `timezone` (e.g. `Europe/Berlin`) for Milanote's own export.
Leave `url` at `https://app.milanote.com`.

## Actions

Boards and cards are named by id. Every action that takes a `board` also
takes the board's URL (`https://app.milanote.com/1Xiq…/board-name`). The
`board` action lists each card's `id`.

| Action | Risk | Notes |
| --- | --- | --- |
| `boards` | read | Your boards as a tree from Home (or from `parent`), `depth` 1–4 (default 2). It opens at most 40 boards per call. `truncated` says when it stopped. |
| `board` | read | Every card on the board, its columns and its Unsorted panel, as `elements` (id, type, section, column, title, text, url, tasks) and as `markdown`. `format`: `both`, `json` or `markdown`. |
| `search` | read | Milanote's own search: matching boards, their path and the matching cards. `sort`: `viewed` or `modified`. |
| `add_note` | write | Plain text, one paragraph a line, on top of the board's Unsorted panel or of a `column`. Undo moves it to the trash. |
| `add_todo` | write | A to-do list with an optional `title` and 1–100 tasks. Undo moves it to the trash. |
| `check_todo` | write | Ticks a task (`done`: true) or unticks it (false), found by task id or exact text. Undo sets it back. |
| `add_link` | write | A link card with Milanote's page preview (title, description, image). Undo moves it to the trash. |
| `update_note` | write | Replaces a note's text. The preview shows before and after. Undo restores the old text with its formatting. |
| `move` | write | To another board (`toBoard`) and/or into a column (`toColumn`). The card lands on top of Unsorted or of the column. Undo puts it back where it was. |
| `archive` | destructive | Moves cards to the board's trash, like the Delete key. The preview lists them. Undo (`restore`) puts them back. |
| `restore` | write | Puts cards from the trash back where they were. |
| `delete` | destructive | Removes cards **already in the trash**, permanently. Archive them first. The preview lists them. Can't be undone. |
| `export` | read | The board as Markdown. `via: conduit` (default) renders it from the board read. `via: milanote` uses Milanote's own Export → Markdown. |

Images and files show up as links in Markdown. Uploading them, comments,
labels, sharing and account settings aren't supported. The module never
changes your password, email or sign-in settings.

## How it works

- **Session.** The cookies stay in memory, are sent only to the Milanote
  address, and never land on disk. Every request carries the `Origin` and
  `Referer` the web app sends, which Milanote's session layer checks on
  changes. If Milanote answers 401, the module signs in again once (with a
  password) and repeats the request. A write is only repeated if nothing was
  sent yet, so a card can't be added twice.
- **Politeness.** One request at a time, at least 0.4 s apart, about as fast
  as you click. A tree walk opens at most 40 boards. When Milanote rate-limits
  the account (HTTP 429), Health turns *degraded* and actions say to wait a
  few minutes.
- **Firewall.** Milanote sits behind AWS WAF. A challenge answer
  (`x-amzn-waf-action`) is reported as *"Milanote asked for a browser
  check"*, never worked around.
- **Writes** go over the same socket.io channel as the web app, using plain
  HTTP long polling rather than a websocket. Each change is one action
  (`ELEMENT_CREATE`, `ELEMENT_UPDATE`, `ELEMENT_MOVE_MULTI`,
  `ELEMENT_SET_TYPE`, `ELEMENT_DELETE`), and Milanote confirms it before the
  action returns.
- **Fixing it.** All of Milanote's URLs, field names and message shapes are
  in `modules/milanote/client.go`. The fake server in `fake_test.go` mirrors
  them. When Milanote changes, record the web app's requests in the browser's
  Network tab, update both, and bump `WireVersion`.

`delete` uses the `ELEMENT_DELETE` action as named in Milanote's web
bundle. It was never seen on a live account, so try it on a test card first.
