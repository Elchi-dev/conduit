# Snyk

Security findings from Snyk: organizations, projects with their latest
issue counts, open issues by severity, and a project's recent test results.
The module is read-only.

**Setup.** Copy your API token (Account settings) or a service account's
token into the vault and enter its reference. Choose the `region` your
tenant is hosted in (`us`, `eu` or `au`) and, optionally, a default
`organization` ID (Organization settings, General) so actions don't need
one.

| Action | Risk | Notes |
| --- | --- | --- |
| `orgs` | read | Organizations the token can see, with ID, name and slug |
| `projects` | read | An organization's projects with type, target file, branch, status, when last tested and the issue counts of that test |
| `issues` | read | Open, unignored issues by severity: for one `project` also by type with the most frequent critical and high titles; for the whole organization summed from each project's latest test, with the most affected projects |
| `tests` | read | A project's latest test snapshots (`limit`, up to 50): when, how (CLI, recurring, web), dependency count, vulnerability and license issues by severity |

Organization and project IDs must be UUIDs, so input can't reach other API
paths. Pages are followed by their cursor only, never by an address the
server sends. `tests` uses Snyk's v1 project history API, the rest the REST
API (version 2024-10-15). Redirects to another host are refused.
