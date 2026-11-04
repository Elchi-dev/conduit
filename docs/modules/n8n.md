# n8n

Workflows and executions on an n8n server through its public API: what
ran, what failed, and turning workflows on or off.

**Setup.** In n8n, Settings, n8n API, create an API key and store it in the
vault. Enter the server address, such as `https://n8n.example.com`.

| Action | Risk | Notes |
| --- | --- | --- |
| `workflows` | read | Every workflow (up to 1,000) with active state, tags, node count, last change and a link. `active` filters. |
| `activate` | write | Turns on the workflow's triggers. The preview shows the change; undo deactivates it. |
| `deactivate` | write | Turns them off; undo activates it. |
| `executions` | read | Recent executions, newest first, with workflow name, status, mode, duration and a link. `workflow`, `status` and `limit` filter. Execution data isn't fetched. |
| `failed_executions` | read | The same, only those that ended in an error. |

n8n's public API has no call that runs a workflow, so this module doesn't
start one. A workflow with a Webhook trigger can be called with the
[web](web.md) module.

**Security.** The key travels in `X-N8N-API-KEY`; the client refuses
redirects to another host. Workflow ids are checked (letters and digits)
before they go into a request path or query.
