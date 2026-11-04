# monday.com

Boards and items on monday.com with their column values, creating items,
changing a column's value and posting updates.

**Setup.** In monday.com, open your avatar, Developers, then My access
tokens, and copy your personal API token; store it in the vault and enter
its `secret://` reference. The token acts as you.

| Action | Risk | Notes |
| --- | --- | --- |
| `boards` | read | Active boards: name, kind, workspace, item count, link. |
| `items` | read | Items on a `board` with their group and column values by title. Pass the `cursor` an answer returns to get the next page. |
| `item` | read | Every column with its id, title, type and text (for `change_column_value`), and the 20 latest updates. |
| `create_item` | write | Adds an item to a board, optionally in a `group` and with `columns` given as column id to value, as you'd type them (`{"status":"Working on it","date4":"2026-12-01"}`). Undo deletes it. |
| `change_column_value` | write | Sets one column to a value as you'd type it; empty clears it. Says "nothing to change" when it already has that value. Undo puts the old value back for text, number, status, dropdown and date columns. |
| `add_update` | write | Posts an update (a comment) on an item. Undo deletes it. |
| `delete_update` | destructive | Deletes an update. |
| `delete_item` | destructive | Moves the item to monday.com's trash. The preview shows the item. |

Every changing action except `delete_update` has a preview.

**Security.** The token goes in the `Authorization` header, and the client
won't follow a redirect to another host or from https to http. Every value
travels as a GraphQL variable; queries are fixed text. Ids must be numbers,
and column and group ids plain identifiers, before any request.

## Notes

- Email and phone columns are left out of answers and aren't set or
  changed from Conduit; computed columns (formula, mirror, connections,
  files and the like) can't be set with a simple value.
- Update text is posted as plain text, so it can't @-mention people;
  wildcard mentions such as `@everyone` are refused.
