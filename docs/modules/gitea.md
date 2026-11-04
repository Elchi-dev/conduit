# Gitea / Forgejo

Repositories, pull requests, issues and Actions runs on a self-hosted Gitea
or Forgejo server, or on Codeberg.

**Setup.** Create an access token (Settings, Applications) with read and
write access to repositories and issues, store it in the vault, and enter the
server address, such as `https://git.example.com`.

| Action | Risk | Notes |
| --- | --- | --- |
| `repos` | read | Repositories the token's user can see (up to 50). |
| `pulls` | read | Open pull requests with base and head branch. |
| `issues` | read | Open issues (pull requests left out). |
| `runs` | read | Actions workflow runs. Needs Gitea 1.23+ or a recent Forgejo. |
| `create_issue` | write | Undo closes it. |
| `close_issue` / `reopen_issue` | write | Each one's undo is the other. |
| `comment` | write | On an issue or pull request. Undo deletes the comment. |
| `delete_comment` | destructive | The preview shows the comment. |
| `merge` | destructive | `method` is merge, squash or rebase; `deleteBranch` removes the head branch. The preview shows the title, head and base. Can't be undone from Conduit. |

`repo` is always `owner/name` using Gitea's allowed characters, and numbers
must be positive, so input can't reach other API paths.

**Servers inside a WireGuard network.** A Forgejo or Gitea server that is
only reachable through WireGuard (a homelab box, a server behind a VPN) works
without any VPN client on this machine: add the network under Networks
(paste its wg-quick file), then pick it in the connection's settings
(Network). The module's API calls to the network's addresses then go through
Conduit's own userspace tunnel. See
[docs/architecture/networks.md](../architecture/networks.md).
