# SonarQube

Code quality from a SonarQube server or SonarCloud: projects, the quality
gate of a project, branch or pull request, open issues by severity and
type, recent analyses and security hotspots. The module is read-only.

**Setup.** Enter the address (`https://sonar.example.com`, with a path if
SonarQube is served under one, or `https://sonarcloud.io`), create a user
token (My Account, Security) for an account with Browse on the projects
you want, and store it in the vault. SonarCloud also needs the organization
key. For a self-signed certificate, enter its SHA-256 `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `projects` | read | Project keys and names (`search` narrows, 2 characters or more), with visibility and last analysis date when the token has Administer (otherwise the Browse-level list without them). |
| `quality_gate` | read | Whether a `project` (or its `branch` or `pullRequest`) passes its quality gate, the failing metrics and every condition with comparator, threshold and actual value. |
| `issues` | read | Open (unresolved) issues counted by severity and by type. |
| `analyses` | read | The latest analyses (`limit`, up to 50) of a project or branch with date, version, revision and events such as quality gate changes. |
| `hotspots` | read | Security hotspots to review, counted by vulnerability probability, and how many are reviewed. |

**Security.** The token goes as HTTP basic auth (the token as user name,
which every SonarQube version and SonarCloud accept), and the client
follows redirects only within the same host and never from https to http.
Project keys, branches, pull request IDs, the organization and searches
are checked before they reach a request.
