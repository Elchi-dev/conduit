# Notion

Search a Notion workspace, read pages as Markdown, query databases, add
pages to a database, append content to a page, and move pages and blocks to
the trash and back.

**Setup.** Open [notion.so/profile/integrations](https://www.notion.so/profile/integrations),
create an internal integration for your workspace, give it the capabilities
you want (read content; insert and update content for the writes) and store
its secret in the vault. An integration sees nothing until you share pages
with it: on a page or database, open the ••• menu, Connections, and add the
integration (sub-pages inherit it).

The module speaks Notion API version `2026-03-11`, so databases are read
through their data sources and trashing uses `in_trash`. A database with
several data sources needs `dataSource` (its name or id) on queries and new
pages; `database` lists them.

| Action | Risk | Notes |
| --- | --- | --- |
| `search` | read | Pages and databases whose title matches `query`, most recently edited first; `type` narrows to `page` or `database`. Titles and links only. |
| `read_page` | read, sensitive | The page's properties and its content as Markdown: headings, lists (nested), to-dos, quotes and callouts, code, tables, dividers, bookmarks, and markers for sub-pages, databases and files. Nested blocks go `depth` levels deep (default 3, at most 5), the text stops at `maxChars` (default 20,000) and at most 60 block requests are made; `truncated` says when something was cut. Notion-hosted files come with short-lived signed links, which are left out. Page content is private, so input and output stay out of the audit log, approvals and events. |
| `database` | read | The database's data sources and each one's property names and types, to write filters and new pages. |
| `query_database` | read | Rows with an optional Notion `filter` and `sorts` (passed through as Notion defines them), up to `limit` (default 50, at most 500), each with its title, link and property values flattened to text. |
| `create_page` | write | A row in a database: `title`, `properties` by name with plain values (text, numbers, true/false, select and status names, a list of names for multi-select, a date or `{start, end}`, page ids for relations), and optional `content`. Values are converted using the data source's schema; unknown properties and types it can't set (people, files) are refused before anything is sent. With a preview; undo moves the page to the trash. |
| `append_blocks` | write | `content` as simple Markdown (`#` headings, `-` bullets, `1.` numbers, `- [ ]` to-dos, `>` quotes, `---`, code fences, paragraphs), up to 100 blocks, at the end of a page or block. The preview lists the blocks; undo trashes them. |
| `trash_blocks` / `restore_blocks` | write | Up to 100 block ids. The preview shows each block's type and text; each undoes the other. |
| `archive_page` | write | Moves a page to the trash, where Notion keeps it for 30 days, so it's a write with undo (restore) rather than destructive. With a preview. |
| `unarchive_page` | write | Restores a page from the trash; undo trashes it again. |

Pages, databases and blocks can be given as an id (with or without dashes)
or a `notion.so` / `notion.site` link. Notion limits integrations to about
three requests a second; a long page read makes several.

**Security.** The secret goes in the `Authorization` header with a fixed
`Notion-Version`, and the client won't follow a redirect to another host.
Every id is normalised to a UUID before it reaches a request path, including
ids that come back from Notion (data sources, child blocks), and links are
only read from Notion's own hosts.
