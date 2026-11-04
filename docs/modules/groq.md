# Groq

The models a [GroqCloud](https://console.groq.com/) API key can use, with
owner, whether each is active, its context window and largest completion.
Read-only; nothing here sends prompts or spends credit.

**Setup.** Create an API key at console.groq.com, API Keys, and store it
in the vault.

| Action | Risk | Notes |
| --- | --- | --- |
| `models` | read | Id, owner, active, context window, largest completion (when Groq gives it) and creation date. `search` in id or owner, `active` to keep active or inactive models, `limit` (50, at most 200). |

Health lists the models and shows how many the key can use.

**Notes.**

- Usage and spend aren't included: Groq's API has no usage or billing
  endpoint. Usage is on the GroqCloud console's Usage page.
- An owner that is an organization or user id shows as `your organization`.

**Security.** The key goes in the `Authorization` header to `api.groq.com`
only; redirects are followed within the same host only. Searches are
checked before they reach a request.
