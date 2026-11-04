# Portainer

Environments, stacks, containers and images on a Portainer server (CE or
Business Edition 2.x).

**Setup.** In Portainer, My account, Access tokens, add a token and store it
in the vault. It acts with that user's rights, so a user that only sees some
environments limits what Conduit can do. Enter the server address, such as
`https://portainer.example.com:9443`.

| Action | Risk | Notes |
| --- | --- | --- |
| `environments` | read | Each environment with type, state and its last snapshot's container, stack and image counts. |
| `stacks` | read | Stacks (all, or of one `environment`) with type, state and Git source. Environment variables are never returned. |
| `start_stack` | write | The preview shows the state change. Undo stops it. |
| `stop_stack` | destructive | Stops every container of the stack. Undo starts it. |
| `redeploy_stack` | destructive | A Git stack pulls its repository again; any other compose stack is redeployed from its current compose file and variables. `pullImage` (default true) pulls newer images. The preview says which. Can't be undone. Kubernetes stacks aren't supported. |
| `containers` | read | Containers of a Docker `environment`, running and stopped, with their stack. |
| `start_container` | write | Undo stops it. |
| `stop_container` | destructive | Undo starts it. |
| `restart_container` | destructive | With a preview. |
| `images` | read | Images of a Docker `environment` with tags and size. |

Stopping and restarting interrupt a service, so they are destructive, like
the [Docker](docker.md) module's.

**Security.** The token travels in `X-API-Key`; the client refuses redirects
to another host (Go would otherwise forward that header). Environment and
stack ids must be positive numbers and container ids or names are checked
before they go into a request path.
