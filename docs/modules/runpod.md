# RunPod

A [RunPod](https://www.runpod.io/) account: GPU pods with their status and
cost per hour, starting and stopping pods, serverless endpoints, and the
balance with what the account spends per hour right now.

**Setup.** Create an API key at runpod.io, Settings, API Keys, and store it
in the vault. A read-only key is enough to look; starting and stopping pods
needs a read/write key.

| Action | Risk | Notes |
| --- | --- | --- |
| `pods` | read | Each pod: id, name, status, type, GPU type and count, cost per hour, vCPUs, memory, container and volume disk, image, location, uptime. `running` filters. Also the total cost per hour of the running pods. |
| `start_pod` | destructive | Starts a stopped pod on its GPUs. It's destructive because it spends money by the hour; the preview shows the GPU and the hourly cost. A running pod answers "nothing to change". The result gives the hourly rate RunPod bills after the start. Undo stops it again. |
| `stop_pod` | destructive | Stops a running pod: whatever runs on it ends and its container disk is cleared, while the volume stays (billed for storage). The preview names the GPU, the hourly cost and the volume. Undo starts it again, except for a spot pod, which needs a bid to start (the preview says so). |
| `endpoints` | read | Serverless endpoints: GPU types, minimum and maximum workers, idle timeout, scaler and locations. |
| `balance` | read | Credit left, current spend per hour, the spend limit, and how many hours the balance lasts at this rate. |

**Risk levels.** Starting a GPU pod is destructive rather than write, the
same as resuming a Hugging Face Inference Endpoint: an agent allowed to
write shouldn't be able to start spending money by the hour. Cloud servers
(AWS, Vultr) start at write because a stopped server costs about the same.

**Security.** The API key goes in the `Authorization` header to
`api.runpod.io` only; redirects are followed within the same host only.
Every GraphQL query is fixed and names its fields; pod ids travel as
variables, after a check. A pod's environment variables, ports and
registry credentials are never asked for.

## Notes

- Spot (interruptible) pods need a bid to start, which is left to the
  RunPod console.
- A pod whose GPUs were rented out while it was stopped may fail to start
  until a GPU on its machine is free; RunPod's message says so.
