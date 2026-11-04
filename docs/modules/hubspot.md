# HubSpot

Contacts, companies, deals, tickets and notes in HubSpot CRM; adding and
deleting notes, and moving deals between stages.

**Setup.** In HubSpot, open Settings, Integrations, Private Apps, and create
an app with the CRM scopes you need: `crm.objects.contacts.read`,
`crm.objects.companies.read`, `crm.objects.deals.read`, `tickets` (and the
matching `.write` scopes to add notes or move deals). Store its access token
(`pat-…`) in the vault.

| Action | Risk | Notes |
| --- | --- | --- |
| `contacts` | read, sensitive | Finds contacts by name, email or phone (`search`), or lists the latest: name, email, phone, company, job title, lifecycle stage. |
| `companies` | read | Name, domain, industry, city, country, size and lifecycle stage. |
| `deals` | read | Name, amount and currency, pipeline and stage by label, whether the stage is closed, close date and owner id. |
| `tickets` | read, sensitive | Subject (a ticket from the inbox takes the customer's email subject), pipeline and stage, priority and category. Not the ticket's content. |
| `notes` | read, sensitive | The notes on a contact, company, deal or ticket, newest first, as plain text. |
| `add_note` | write, sensitive | Adds a note to a record. Undo deletes it. |
| `delete_note` | destructive | Deletes a note; the preview shows when it was written and which records it's on. |
| `set_deal_stage` | write | Moves a deal to another stage of its pipeline, by stage id or label. Says "nothing to change" when it's there already; undo moves it back. |

All listings page with `after` and take up to 100 records at a time.

**Notes.**

- Stage labels come from the account's pipelines; a stage outside the deal's
  pipeline is refused with the list of valid ones. A stage id wins over a
  label, and a label two stages share is refused (give the id).
- Notes are stored as HubSpot's rich text; Conduit escapes what it writes and
  strips formatting when it reads.

**Security.** The token goes in the `Authorization` header, only to
`api.hubapi.com`, and the client won't follow a redirect to another host.
Ids are checked before they reach a request path. Personal data stays in the
sensitive actions, and error text from HubSpot is scrubbed of emails and
phone numbers.
