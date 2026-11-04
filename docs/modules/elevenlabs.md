# ElevenLabs

An [ElevenLabs](https://elevenlabs.io/) account: the subscription with
characters used and left, character usage by day, voices, and the
generation history. Everything is read-only; nothing here spends
characters.

**Setup.** Create an API key at elevenlabs.io, Developers, API Keys, and
store it in the vault. A restricted key needs read access to User, Voices
and History.

| Action | Risk | Notes |
| --- | --- | --- |
| `subscription` | read | Plan and status, characters used, limit and left, when they reset, whether the limit can be extended, voice slots used and allowed, and the next invoice. |
| `usage` | read | Characters used per day over the last `days` (30, at most 90), with the total. |
| `voices` | read | Id, name, category, labels, description, created, and whether it's yours. `category` filters (`premade`, `cloned`, `generated`, `professional`, …). Voice samples, previews and verification recordings are never read. |
| `history` | read, sensitive | Recent generations, newest first: date, voice, model, characters used, source and the text spoken (first 500 characters). The text can hold personal data, so the action is sensitive and kept out of the audit log. `limit` (20, at most 100), `voice` filters, `after` takes the `next` value of an earlier page. |

**Security.** The API key goes in the `xi-api-key` header to
`api.elevenlabs.io` only; redirects are followed within the same host
only, so the header can't be forwarded elsewhere. Voice and history ids are
checked before they reach a query.

## Notes

- Health turns degraded when the plan's characters are used up, until they
  reset.
