# Mealie

A Mealie recipe server: search recipes, read a recipe's ingredients and
steps, see the meal plan for today or this week, and work with shopping
lists (read them, add items, check them off or change them, remove them).
It uses Mealie's REST API with an API token; Mealie 2 (households) and
Mealie 1 (groups) both work, picked from the server's version.

**Setup.** In Mealie open your profile → *API Tokens*, create one and store
it in the vault. Enter the address, such as `https://mealie.example.com`.
The token acts as your user, so it sees your household's meal plan and
shopping lists.

| Action | Risk | Notes |
| --- | --- | --- |
| `search_recipes` | read | Recipes matching `query` (Mealie searches names, descriptions and ingredients), up to `limit` (50), with times, yield, rating, tags and categories. Without a query, recipes by name. |
| `recipe` | read | One recipe by slug: servings, times, source, ingredients (with section titles), steps, notes and nutrition. |
| `meal_plan` | read | Planned meals by day for `today` (the default), this `week` (Monday to Sunday) or `start`..`end` (at most two months), breakfast to dessert. |
| `shopping_lists` | read | The lists with their ids. |
| `shopping_list` | read | A list (by name or id) with its items, unchecked first; `checked: false` leaves checked ones out. |
| `add_shopping_item` | write | Adds `note` with a `quantity` (1 by default). Mealie merges an item into a matching unchecked one; then undo sets that item back to what it was, otherwise undo removes the new item. |
| `update_shopping_item` | write | Checks or unchecks an item or changes its text or quantity. Undo restores it. |
| `remove_shopping_item` | destructive | Deletes an item. Undo adds it again (as a new item with the same text, quantity, food, unit and label). |

Every write has a preview.

**Security.** The token goes in the `Authorization` header; the client
won't follow a redirect to another host or from https to http. Recipe slugs,
list and item ids (UUIDs) and dates are checked before they're put in a URL.
