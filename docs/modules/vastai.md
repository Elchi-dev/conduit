# Vast.ai

A [Vast.ai](https://vast.ai/) account: rented GPU instances with their
status and cost per hour, starting, stopping and destroying them, and the
account's credit.

**Setup.** Create an API key at cloud.vast.ai, Account, Keys, and store it
in the vault. A restricted key needs instance read, and instance write to
start, stop or destroy.

| Action | Risk | Notes |
| --- | --- | --- |
| `instances` | read | Each instance: id, label, status, GPU type and count, cost per hour, storage price, CPU cores, memory, disk, image, location, GPU use, whether it's interruptible and when it started. `running` filters. Also the total cost per hour of the running ones. |
| `start_instance` | destructive | Starts a stopped instance. It's destructive because it spends money by the hour; the preview shows the GPU and the hourly cost, and says when the instance is interruptible (a bid). One already meant to run answers "nothing to change". Undo stops it again. |
| `stop_instance` | destructive | Stops a running instance: whatever runs on it ends, its disk is kept (and billed), and its GPUs may be rented to someone else meanwhile. Undo starts it again. |
| `destroy_instance` | destructive | Deletes the instance and everything on its disk. The preview names the GPU, cost, disk size and status. No undo. |
| `balance` | read | Credit left, how many instances run, what they cost per hour together, and how many hours the credit lasts at that rate. |

**Risk levels.** Starting a GPU instance is destructive for the same reason
as RunPod's `start_pod`: it starts spending money by the hour.

**Security.** The API key goes in the `Authorization` header to
`console.vast.ai` only; redirects are followed within the same host only.
Instance ids must be plain numbers before they reach a request path.
Instances are decoded field by field, so SSH and Jupyter details, the
environment, the start script and the instance's own API key are never
read; neither are the account's e-mail or keys.

## Notes

- A stopped instance whose GPUs were rented out waits for them when it's
  started again, which can take a while.
