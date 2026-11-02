# Docker

Containers and Compose stacks through the Docker Engine API.

## Settings

| Mode | Connects to |
| --- | --- |
| `local` | This machine's socket (`/var/run/docker.sock`, or Docker Desktop's pipe on Windows) |
| `ssh` | The Docker socket on a remote server, tunnelled through SSH (same SSH settings and host-key pinning as the Server module) |
| `tcp` | A Docker API port, `host:port`. Unencrypted; use only on a trusted network |

## Actions

| Action | Risk | Notes |
| --- | --- | --- |
| `containers` | read | All or running only, with Compose project and published ports |
| `stacks` | read | Compose projects with running/total counts |
| `stats` | read | CPU % and memory of running containers |
| `logs` | read | Recent lines, stdout and stderr merged with timestamps |
| `images` | read | Tags, size, created |
| `start`, `unpause` | write | Undo stops / pauses again |
| `pause` | write | Undo resumes |
| `stop` | destructive | Undo starts again; dry run shows current state |
| `restart` | destructive | Dry run shows current state |
| `stack_action` | destructive | Start, stop, restart, pause or resume every container of a Compose project |

Health shows the Docker version and how many containers are running.
