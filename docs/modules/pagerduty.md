# PagerDuty

Open incidents and who's on call; acknowledge and resolve incidents; open an
incident from an automation and resolve it again.

**Setup.** Either part, or both:

- **To see and handle incidents**, create a REST API key (Integrations, API
  Access Keys) and store it in the vault. Changes are recorded as a
  PagerDuty user, so also enter that user's email under **From**.
- **To open incidents**, add the Events API v2 integration to a service
  (Service, Integrations, Add, Events API V2) and store its integration key
  as the **routing key**.

| Action | Risk | Notes |
| --- | --- | --- |
| `incidents` | read | Triggered and acknowledged, newest first, with service and assignees |
| `oncall` | read | Who's on call now per escalation policy and level |
| `acknowledge` | destructive | Stops the incident escalating to further people |
| `resolve` | destructive | Alerting and escalation stop even if the problem goes on. Not reversible in PagerDuty |
| `trigger` | destructive | Pages whoever is on call for the service. Opens an incident with a summary, severity and optional dedup key. Undo resolves it. |
| `resolve_event` | destructive | Resolves the incident an event opened, by dedup key |

Health is degraded while incidents are triggered and unacknowledged.

**Security.** Use a read-only API key if Conduit should only show incidents.
A routing key can only send events to its one service, which makes it the
safest credential for automations that open incidents.
