# GrowthBook

Features with their state in each environment, turning a feature on or
off in one environment, and experiments, on GrowthBook Cloud or a
self-hosted GrowthBook.

**Setup.** In GrowthBook, open Settings, API Keys and create a secret key:
read-only to look, admin to turn features on and off. Store it in the
vault. Leave the address as `https://api.growthbook.io` for GrowthBook
Cloud, or enter your GrowthBook API's address (port 3100 by default), such
as `https://growthbook-api.example.com`. For a self-signed certificate,
set `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `features` | read | Key, value type, project, description, tags, archived, last update, and in each environment whether it's on, its rule count and its active rules by kind (`force`, `rollout`, `experiment-ref`). `project` filters. |
| `turn_on` | destructive | Turns a feature on in one environment. The preview names the project, environment and feature, with the state before and after. Undo turns it off again. |
| `turn_off` | destructive | Turns a feature off in one environment. The preview and undo work the same way. |
| `experiments` | read | Id, name, tracking key, type, status, project, hypothesis, tags, variations by name, phases with start, end and coverage, and the result (status, winner, released variation). `project` filters. |

When the feature is already in the state asked for, the action answers
"nothing to change" and leaves it alone. Both actions use GrowthBook's
toggle endpoint with a reason for the audit log (`reason`, or a note that
it was done through Conduit); it changes only that environment's switch,
so rules and values stay as they are.

**Security.** The key goes in the `Authorization` header, and the client
won't follow a redirect to another host or from https to http. Feature
keys, environment ids and project ids are checked before any request.
Rule conditions, targeting conditions, values and owners can name users or
carry configuration, so they are never returned; rules are counted by kind.
SDK connections and their client keys aren't read at all.

## Notes

- GrowthBook's toggle doesn't take a revision, so a turn is a plain on or
  off rather than a compare-and-set.
