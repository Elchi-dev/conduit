# Notes

Markdown notes in a folder on this computer, for people and agents: runbooks,
findings, to-dos. One instance; the folder defaults to `notes` in Conduit's
data folder, and any folder of `.md` files works (an Obsidian vault, say).

| Action | Risk | Notes |
| --- | --- | --- |
| `list` | read | Newest first, with the first heading as title |
| `read` | read | |
| `search` | read | Names and text, with an excerpt |
| `write` | write | Creates or replaces; undo restores the previous version or removes a new note |
| `append` | write | Adds text at the end; undo restores |
| `delete` | destructive | Undo brings it back |
| `restore` | write | Used by undo |

Names are paths inside the folder (`runbooks/db-failover`); `..`, absolute
paths and hidden files are refused, so a note can never be written outside
the folder. Hidden folders (`.obsidian`, `.git`) are skipped. Notes are at
most 1 MiB.

Agents can keep notes between conversations: let them `append` to a
`journal` note without asking, and keep `write` and `delete` on ask.
