# Hugging Face

A [Hugging Face](https://huggingface.co/) account through the Hub API:
who the token belongs to, your models, datasets and Spaces, a Space's
runtime, restarting and pausing Spaces, and Inference Endpoints with
their state, scaling to zero, pausing and resuming.

**Setup.** Create an access token at huggingface.co, Settings, Access
Tokens, and store it in the vault. A read token is enough to look;
restarting and pausing Spaces and managing endpoints need a write token,
or a fine-grained one with those permissions (and the organization's,
for its Spaces and endpoints).

| Action | Risk | Notes |
| --- | --- | --- |
| `whoami` | read | Account name, full name, type, Pro, organizations, and the token's name and role. Never the token or the e-mail address. |
| `models` | read | Models of `author` (you by default), recently changed first: task, library, downloads, likes, private, gated. `search`, `limit` (50, at most 100). |
| `datasets` | read | The same for datasets. |
| `spaces` | read | The same for Spaces, with their SDK. |
| `space_status` | read | A `space`'s (owner/name) stage (RUNNING, BUILDING, SLEEPING, PAUSED, RUNTIME_ERROR, …), hardware now and requested, sleep time and error message. |
| `restart_space` | destructive | Restarts a Space; `factory` rebuilds it from scratch. Also wakes a sleeping or paused Space, which starts billing for paid hardware. Preview shows its stage and hardware. |
| `pause_space` | destructive | Pauses a Space: it stops billing and stays off until restarted. |
| `endpoints` | read | Inference Endpoints of `namespace` (you by default): state, model, task, hardware, provider and region, replicas ready and wanted, scaling, shortened address. |
| `endpoint_status` | read | One endpoint by `name`. |
| `scale_endpoint_to_zero` | destructive | Stops the endpoint's replicas so it stops billing; the next request wakes it. It saves money and the endpoint comes back on its own, but it interrupts whoever uses it: the cold start can take minutes and fail requests meanwhile, so it's destructive like `pause_endpoint`. |
| `pause_endpoint` | destructive | Pauses an endpoint: requests fail until it's resumed. |
| `resume_endpoint` | destructive | Starts a paused or scaled-to-zero endpoint. Destructive because its hardware is billed by the hour from then on; the preview names the hardware. |

Every action that changes something has a preview.

**Security.** The token goes in the `Authorization` header to
`huggingface.co` and `api.endpoints.huggingface.cloud` only; redirects
are followed within the same host only, never from https to http.
Accounts, Space ids and endpoint names are checked before they reach a
request path, so `..`, extra slashes and query strings are refused.
