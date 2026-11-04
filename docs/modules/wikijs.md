# Wiki.js

List and search a Wiki.js 2.x wiki, read a page's source as Markdown, and
create and edit pages. Every edit can be undone: the undo puts back the
version the page had before, as long as nobody has edited it since.

**Setup.** In Wiki.js, open Administration, then API Access, turn the API
on and create a key for a group with the permissions the agent needs
(`read:pages` and `read:source` to read, `write:pages` to create and edit,
`read:history` for undo). Wiki.js returns a page's full record to keys whose
group also has `manage:pages` for that page, so give the group that too, or
use a key of the Administrators group. Store the key in the vault and enter
Wiki.js's address, such as `https://wiki.example.com`. For a self-signed
certificate, pin its SHA-256 `fingerprint`.

Set `public` to say who can read the wiki. It's on by default, matching
Wiki.js's default Guests group, which can read every page. Turn it off when
the Guests group can't read pages. `locale` (default `en`) is the locale of
page paths when an action doesn't give one.

| Action | Risk | Notes |
| --- | --- | --- |
| `pages` | read | Pages, most recently updated first: id, path, locale, title, description, tags, published and link. Filter by `locale` and `tags`; `limit` up to 500. No page text. |
| `search` | read | Wiki.js's search engine, optionally under a `path` or in a `locale`. Id, title, description, path and link. |
| `read_page` | read, sensitive | By `id`, or `path` (and `locale`). The source up to `maxChars` (default 50,000) with title, description, tags, editor, published, whether guests can read it, and dates. Kept out of the audit log, approvals and events. |
| `create_page` | write | A Markdown page at `path` with `title`, `content`, `description` and `tags`. On a public wiki it's created unpublished, so only editors see it until it's published with `update_public_page`. |
| `update_page` | write | Changes `title`, `description` or `content` (only the fields given), and `published`. For pages guests can't read: on a private wiki, or unpublished pages on a public one (so unpublishing a page guests can read is `update_public_page`). The preview shows the lines added and removed and the first changed lines; the same content gives "nothing to change". Undo puts back the previous version. |
| `update_public_page` | destructive | The same, for a published page on a public wiki, or to publish a page there (`published: true`). What it writes is public at once. Undo puts back the previous version. |
| `restore_version` | write | The undo of `update_page`: puts the page's title, description, content and published state back as they were before its latest edit. Refused when guests can read the page or the version put back would publish it. |
| `restore_public_version` | destructive | The undo of `update_public_page`: the same, when guests can read the page, or putting the earlier version back publishes it. |

**Edits and undo.** Before saving, the module asks Wiki.js whether the page
changed since it was read, and refuses the edit if it did. Wiki.js saves
the page as it was before each edit in its history; the undo names that
version by its id and the time the edit saved the page, so the undo token
holds no page text. `restore_version` goes ahead only while the page is
still exactly as the edit left it and that version is still the one before
the latest edit; otherwise it changes nothing, and the page's history in
Wiki.js still has every version.

**Privacy.** Reading a page is sensitive. Previews quote only lines of the
new content (which the agent wrote); removed lines are counted and named by
line number, never quoted. An undo's preview and result quote no lines at
all, since what it puts back is the page's own earlier content.

**Security.** The key goes in the `Authorization` header, and the client
won't follow a redirect to another host or from https to http. Every value
travels as a GraphQL variable, never inside the query. The page's script
and style fields (`scriptJs`, `scriptCss`) aren't inputs: an edit only sends
them back as Wiki.js returned them, so an agent can't add page scripts. Ids must be positive
numbers, paths letters, digits, `-`, `_` and `/` (as Wiki.js accepts them),
and content at most 1 MiB, before any request is sent. Server messages are
redacted before they're shortened.

**Notes.** Wiki.js 2's update replaces every field, so each edit sends the
page's other fields (tags, path, editor, scripts, publishing dates) back as
they are. Wiki.js answers an unknown key as if a guest had asked, so the
health check asks for the key's own profile to tell them apart. Whether
guests can read a page also depends on per-path page rules in Wiki.js,
which the API doesn't show to a key; the `public` setting decides. There's
no way to delete pages here.
