# Mistral AI

The models a [Mistral AI](https://mistral.ai/) API key can use: base
models and your fine-tuned ones, with context length, capabilities,
aliases and deprecation dates. Read-only; nothing here sends prompts or
spends credit.

**Setup.** Create an API key in the Mistral console (API keys) and store
it in the vault.

| Action | Risk | Notes |
| --- | --- | --- |
| `models` | read | Id, name, type (`base` or `fine-tuned`), owner, context length, capabilities (chat, FIM, function calling, vision, fine-tuning and so on), aliases, deprecation date and replacement model. `search` in id or name, `type`, `limit` (50, at most 200). |

Health lists the models and shows how many the key can use.

**Notes.**

- Usage and spend aren't included. Mistral's Admin API has a monthly usage
  report, but it's in beta, open to Enterprise plans only with a separate
  Admin key, and its usage lines have no documented fields, so the module
  doesn't read it. Usage is on the Mistral console's Usage page.
- A fine-tuned model's owner that is an organization or user id shows as
  `your organization`.

**Security.** The key goes in the `Authorization` header to
`api.mistral.ai` only; redirects are followed within the same host only.
Searches are checked before they reach a request.
