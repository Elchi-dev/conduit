# Flagsmith

Projects, environments and flags with their state in an environment, and
turning a flag on or off in one environment, on Flagsmith Cloud or a
self-hosted Flagsmith.

**Setup.** In Flagsmith, open Organisation settings, API Keys and create an
admin key; store it in the vault. Leave the address as
`https://api.flagsmith.com` for Flagsmith Cloud, or enter your Flagsmith
API's address, such as `https://flagsmith.example.com`. For a self-signed
certificate, set `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `projects` | read | Id, name and organisation. |
| `environments` | read | A project's environments: id, name, description and whether feature versioning is on. |
| `flags` | read | A project's flags: id, name, type, description, default, tag count and archived. With `environment` (name or id), also whether each is on there and how many segment overrides it has. |
| `turn_on` | destructive | Turns a flag (by name or id) on in one environment (by name or id). The preview names the project, environment and flag, with the state before and after. Undo turns it off again. |
| `turn_off` | destructive | Turns a flag off in one environment. The preview and undo work the same way. |

When the flag is already in the state asked for, the action answers
"nothing to change" and leaves it alone. The change sends only `enabled`,
so the flag's value and its segment and identity overrides stay as they
are. The undo names the environment and flag by id.

**Security.** The key goes in the `Authorization` header, and the client
won't follow a redirect to another host or from https to http. Project ids,
flag names and environment names are checked before any request.
Environment keys (the SDK keys) are read only to build request paths and
are never returned or kept in an undo; since a transport error or a
server's error text can quote the request path, the key is cut out of
every error. Flag values and identity overrides,
which can hold configuration or user identifiers, are never returned.

## Notes

- In an environment with feature versioning, changes are published as
  versions; the actions (previews included) explain this and leave the
  flag to the Flagsmith dashboard.
- Flagsmith's feature states don't take a version, so a turn is a plain
  on or off rather than a compare-and-set.
