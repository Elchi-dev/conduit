# DefectDojo

Products, engagements and open findings by severity from DefectDojo, and
closing, verifying, risk-accepting or reopening a finding.

**Setup.** In DefectDojo, open your user menu, API v2 Key, and store the key
in the vault. Enter DefectDojo's address, such as
`https://defectdojo.example.com`. The key acts with its user's permissions.
For a self-signed certificate, set `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `products` | read | Id, name, product type, business criticality, lifecycle, finding count and when created. |
| `engagements` | read | Id, name, product, type, status, start and end dates, and whether active, newest first. `product` limits it to one product. |
| `findings` | read | Open findings (active, not mitigated, duplicate, false positive, out of scope or risk-accepted) counted by severity, and the most severe first with title, severity, CVE and other ids, CWE, CVSS, component and version, file and line, test and whether verified. `product`, `engagement` and `severity` filter; `limit` up to 200. |
| `close_finding` | destructive | Marks a finding mitigated and inactive, with an optional `note`. The preview shows the finding and its state before and after. Undo reopens it. |
| `verify_finding` | destructive | Marks a finding verified, or unverified with `verified: false`. Undo sets it back. |
| `risk_accept_finding` | destructive | Accepts a finding's risk, which takes it out of open findings. Undo reopens it. |
| `reopen_finding` | write | Makes a closed or risk-accepted finding active again. Undo closes or risk-accepts it as it was. |

A finding already in the state asked for is left as it is. After a change,
the finding is read back; a server that kept it as it was makes the action
fail with that explanation.

**Security.** The key goes in the `Authorization` header, and the client
won't follow a redirect to another host or from https to http. Ids are
checked as numbers before they reach a request. Descriptions, steps to
reproduce and request and response pairs aren't read, since they hold
scanner payloads; titles and file paths are cut short with credentials
masked.

**Notes.** `risk_accept_finding` uses simple risk acceptance, which is
turned on per product (Edit product); full risk acceptances with owners and
expiry are made in the web interface.
