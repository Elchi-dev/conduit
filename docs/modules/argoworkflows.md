# Argo Workflows

An Argo Workflows server through its API: workflows with their phase,
progress and steps, workflow templates with their parameters, submitting a
workflow from a template, and stopping, terminating or retrying workflows.

**Setup.** Create a service account for Conduit in the namespace it
should work in, bind it to a role that can get and list workflows and
workflow templates (and create, update and patch workflows to submit,
stop, terminate and retry), and create a token for it, for example
`kubectl create token conduit -n argo --duration=8760h` (or `argo auth
token`; the `Bearer ` prefix is accepted). Store it in the vault and enter
the Argo Server's address, such as `https://argo.example.com:2746`, with
the `namespace` actions use unless they name another (default `argo`). For
a self-signed certificate, enter its SHA-256 `fingerprint`. Health shows
the Argo version and checks the token can list workflows in the namespace.

| Action | Risk | Notes |
| --- | --- | --- |
| `workflows` | read | The last `limit` workflows (up to 100), newest first, optionally by `phase`: phase, progress, template, start, finish, duration, message, and whether it's suspended. |
| `workflow` | read | One workflow: everything `workflows` shows plus entrypoint, parameters (values hidden for names containing password, secret, token, key or credential) and its steps (pods, suspends, skipped steps) in order with phase, duration and message, up to 100. |
| `workflow_templates` | read | Workflow templates with their entrypoint and parameters: default (hidden for secret-looking names), allowed values, description, and whether the value comes from elsewhere. |
| `submit_workflow` | destructive | Submits a new workflow from a workflow `template`, with `parameters`. It runs the template's containers with their service account and can deploy. Only declared parameters are accepted, values must be among the allowed ones when the template lists them, and parameters filled from elsewhere (`valueFrom`) or whose name looks secret are refused. The preview shows every value passed. |
| `stop_workflow` | destructive | Stops a running workflow; exit handlers still run. A finished workflow answers "nothing to change". |
| `terminate_workflow` | destructive | Terminates a running workflow at once, skipping exit handlers. A finished workflow answers "nothing to change". |
| `retry_workflow` | destructive | Retries a failed workflow from its failed steps, running their code again. Refused for a succeeded or still running workflow. |

**Security.** The token goes in the `Authorization` header, and the client
won't follow a redirect to another host or from https to http. Namespaces,
workflow and template names must be valid Kubernetes names, and parameter
names plain identifiers, before they reach a request. Workflow templates'
container specs, environments and outputs are never read, so nothing a
workflow holds inline (or reads from a Kubernetes secret) reaches an
answer; messages are redacted before they're cut.

**Notes.** Cluster workflow templates and archived workflows aren't
covered.
