# Standards

Your standards and toolkits for AI work: how frontends should look, writing
tone, code style, review checklists, commit rules, design tokens, preferred
stacks, things never to do. Every AI connected to Conduit gets them
automatically. One instance; the library lives in `standards` in Conduit's
data folder (set another folder in the module's settings).

## What a standard holds

| Field | Notes |
| --- | --- |
| `id`, `title`, `icon`, `summary` | `id` is made from the title when empty |
| `category` | frontend, design, writing, code, git, review, security, product, custom |
| `tags` | free words, for search |
| `appliesTo` | when the standard applies (below) |
| `priority` | 0–100; higher wins when two standards disagree |
| `enabled` | disabled standards are kept but never handed to an AI |
| `sections` | ordered blocks, any number of each kind |

Section kinds: **principles** (a list), **do and don't** (paired rows),
**rules** (each `must`, `should` or `may`, with an optional reason),
**examples** (good and bad, as code in a language or as text), **tokens**
(groups of key / value pairs; colour groups show swatches, type groups a
type-scale preview), **checklist**, **references** (links) and **notes**
(free Markdown).

**Toolkits** bundle standards ("Frontend kit" = design + accessibility + UI
writing). Each toolkit is an MCP prompt.

### When a standard applies

`appliesTo` entries, any of which matching is enough:

| Entry | Matches |
| --- | --- |
| `*.tsx`, `src/**/*.go`, `.css`, `*.{css,scss}` | a file path the AI is touching (`**` crosses folders; without a slash, the file name) |
| `project:acme-*` | the project or repository name (glob) |
| `frontend`, `email`, `kind:review` | a task kind, guessed from the task's words and file types, or given |
| any other word | the project name, or the word appearing in the task |
| `*` | always |

With no `appliesTo`, a standard applies when the task is of its category.
Task kinds: frontend, design, writing, email, code, git, review, security,
accessibility, product.

## Actions

| Action | Risk | Notes |
| --- | --- | --- |
| `for_task` | read | **The AI entry point.** Task, paths, project (and optionally kinds or a toolkit) in; the enabled standards that apply and one merged Markdown brief out |
| `list` | read | Standards (highest priority first, with section counts) and toolkits |
| `get` | read | One standard as compact Markdown; `format: full` adds its structure |
| `search` | read | Titles, text and tags, with an excerpt |
| `toolkit` | read | A toolkit's standards merged; without an id, all toolkits |
| `history` | read | The last 20 versions; with `version`, that version |
| `export` | read | One standard, one toolkit or the library, as Markdown or JSON |
| `save` | write | Creates or replaces; preview shows before and after; undo restores the previous version |
| `save_toolkit` | write | Same for toolkits |
| `import` | write | Markdown or JSON; preview lists every change; undo puts everything back |
| `delete`, `delete_toolkit` | destructive | Undo brings it back |
| `restore` | write | Puts back a version (used by undo and the history view) |

### The merged brief

`for_task` sorts matching standards by priority, then writes: the list of
standards with why each matched, every MUST rule from all of them under
"Required everywhere here", and then each standard in order. A line that a
higher-priority standard already said is left out of the lower one.

## Every AI gets them

Over MCP (`docs/api/mcp.md`):

- The server's **instructions** tell agents to call `standards__for_task`
  before frontend, design, writing, code, commit or review work.
- Each enabled standard is a **resource**, `conduit://standards/<id>`
  (Markdown).
- Each toolkit is a **prompt**, `standards__<toolkit-id>`, plus
  `standards__for-task` (argument `task`).

Reading a resource or prompt runs `get`, `toolkit` or `for_task` through the
agent rules and the timeline, like any tool call.

## Files and formats

One JSON file per standard (`standards/<id>.json`) and per toolkit
(`toolkits/<id>.json`), so the folder can be kept in git; earlier versions
are in `history/`. A `.seeded` file records that the starter standards
(Frontend design principles, Accessibility, Writing for UI, Git commit
messages, Code review checklist, and two toolkits) were written; deleted
starters don't come back.

The Markdown format has YAML front matter (`id`, `kind`, `title`, `icon`,
`category`, `summary`, `tags`, `appliesTo`, `priority`, `enabled`) and one
`##` heading per section followed by `<!-- section: <kind> -->`. A library
export is several such documents in one file. Exports import back unchanged;
hand-written Markdown works too: headings named Principles, Rules, Do and
don't, Examples, Tokens, Checklist or References become those sections and
any other heading becomes notes.

## Screen

The module's page is a library: categories on the left, toolkits as
shelves, standards as cards. The editor is a structured form (sections can
be added, reordered by dragging or with Alt+↑ / Alt+↓, and removed) with a
live "What the AI sees" pane showing exactly what `get` returns, version
history with a diff and restore, and import and export.

## Suggested agent rules

Let agents run every read action without asking. Keep `save`, `import` and
the deletes on ask, so an agent can propose a standard but you approve it.
