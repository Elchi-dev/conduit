# Dependency-Track

Projects, vulnerability metrics by severity and a project's findings from
OWASP Dependency-Track, and auditing or suppressing a finding.

**Setup.** In Dependency-Track, open Administration, Access Management,
Teams, choose or create a team for Conduit and copy its API key; store it
in the vault. Reading needs `VIEW_PORTFOLIO` (and `VIEW_VULNERABILITY` for
findings); auditing needs `VULNERABILITY_ANALYSIS`. Enter the API server's
address, such as `https://dtrack-api.example.com` (the API server, not the
frontend, when they're separate). For a self-signed certificate, set
`fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `projects` | read | Active projects (all with `includeInactive`) with UUID, name, version, classifier, last BOM import, vulnerabilities by severity and risk score. `search` matches names. |
| `metrics` | read | Vulnerabilities by severity for the whole portfolio or one `project`, with vulnerable components (and projects), suppressed, audited and unaudited findings, policy violations, risk score and when measured. |
| `findings` | read | A project's findings, most severe first: finding id, vulnerability id and aliases, source, severity, CVSS, EPSS, title, component and version, and analysis state. Suppressed ones only with `includeSuppressed`; `severity` filters; `limit` up to 500. |
| `audit_finding` | destructive | Records an analysis on a finding (by its finding id from `findings`): `state`, `justification`, `response`, `details`, a `comment`, and `suppressed` to suppress or unsuppress it. The preview shows the analysis before and after. Undo sets the previous state, justification, response, details and suppression back. |

An analysis already as asked (with no new comment or details) is left as it
is. After a change, a server that kept the state or suppression as it was
makes the action fail with that explanation.

**Security.** The key goes in the `X-Api-Key` header, and the client won't
follow a redirect to another host or from https to http. Project and
finding ids are checked as UUIDs, and states against Dependency-Track's
lists, before they reach a request. Vulnerability descriptions aren't
returned; titles are cut short with credentials masked.

**Notes.** Comments are added to the finding's audit trail and stay there
after an undo.
