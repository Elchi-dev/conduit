# Homebox

Your [Homebox](https://homebox.software) home inventory: find items and
where they are, see warranties running out, add items, change how many you
have and delete them. It uses Homebox's REST API (`/api/v1/items`,
`/locations`), as in the released versions.

**Setup.** Enter Homebox's address, such as `https://homebox.example.com`,
and either the email you sign in with plus your password (stored in the
vault), or, on versions that have them, an API key (also in the vault).
With a password Conduit signs in for a session, keeps it until it's about to
end and signs in again when Homebox ends it early.

| Action | Risk | Notes |
| --- | --- | --- |
| `search_items` | read | Items matching `query`, everywhere or in one `location` (id or name), up to `limit` (100), with quantity, location, labels and asset id; archived ones only with `archived`. |
| `item` | read | One item with its description, manufacturer, model, purchase date, place and price, warranty and insurance. Notes and serial numbers are left out. |
| `locations` | read | Locations with how many items each holds. |
| `warranty_soon` | read | Items whose warranty ends within `days` (60), soonest first, plus ones that ended up to `includeExpired` days ago. Listings don't carry warranties, so it reads up to 500 items one by one (four at a time) and says when there were more. Lifetime warranties are skipped. |
| `add_item` | write | With a preview. Adds `name` to a `location` (id or exact name) with a `quantity` (1) and optional `description`. Undo deletes it. |
| `update_quantity` | write | With a preview. Sets an item's `quantity`. Undo sets it back. |
| `delete_item` | destructive | With a preview. Deletes the item with its attachments and maintenance log; Homebox can't bring it back, so there's no undo. |

**Security.** The password and API key are vault references; the password
is sent only to Homebox's login and never appears in errors. The client
won't follow a redirect to another host or from https to http. Item and
location ids (UUIDs) are checked before they reach a request path. For a
self-signed certificate, pin its SHA-256 `fingerprint`.
