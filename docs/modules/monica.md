# Monica

Your [Monica](https://www.monicahq.com) personal CRM: find contacts, see
upcoming reminders and birthdays, and add notes to a contact. It works with
monicahq.com and self-hosted Monica 4 through the REST API; Monica 5 has no
API yet.

**Setup.** In Monica open Settings → API, create a personal access token and
store it in the vault. Enter Monica's address: `https://app.monicahq.com` or
your own. The token acts as you.

Everything Monica holds is about people, so every action is **sensitive**:
Conduit keeps inputs and outputs out of the audit log, approvals and events
(previews are still shown to whoever decides an approval).

| Action | Risk | Notes |
| --- | --- | --- |
| `contacts` | read, sensitive | Contacts matching `query` (name, nickname, email), or all by first name, up to `limit` (100), with birthday (`--MM-DD` when the year isn't known), starred and deceased. Partial contacts (people only known as someone's relative) are left out. |
| `contact` | read, sensitive | One contact with their description and newest `notes` (5, up to 50). |
| `upcoming` | read, sensitive | Birthdays (with the age they turn, when the year's known) and reminders in the next `days` (30), soonest first. Reminders repeat weekly, monthly or yearly from their start date; Monica's own birthday reminders aren't listed twice. Reads up to 1,000 contacts and 1,000 reminders and says when there were more. |
| `add_note` | write, sensitive | With a preview. Adds a note (`body`, optionally `favorite`) to a `contact`; they aren't sent anything. Undo deletes it: the token holds only the note's number, so the audit log keeps it. |
| `delete_note` | destructive, sensitive | With a preview that quotes the note. Deletes it; Monica can't bring it back. |

**Security.** The token goes in the `Authorization` header and the client
won't follow a redirect to another host or from https to http. Contact and
note ids are checked before they reach a request path. For a self-signed
certificate, pin its SHA-256 `fingerprint`.
