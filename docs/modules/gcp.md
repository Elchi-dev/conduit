# Google Cloud

Google Cloud projects, Compute Engine instances (start, stop, reset) and
Cloud Run services with their revisions and where traffic goes, including
routing it. Conduit signs in with a service-account key and calls the
Google APIs directly.

**Setup.** In the Google Cloud console, open IAM & Admin, Service accounts,
create one for Conduit, then Keys, Add key, JSON. Store the whole
downloaded file in the vault and enter its `secret://` reference; a plain
key is refused. Grant the account roles on the projects it should see:
*Viewer* (or *Browser* plus *Compute Viewer* and *Cloud Run Viewer*) to
watch, *Compute Instance Admin (v1)* to power instances, *Cloud Run
Developer* to route traffic. The Compute Engine, Cloud Run Admin and Cloud
Resource Manager APIs must be enabled. `project` defaults to the key's own
project.

| Action | Risk | Notes |
| --- | --- | --- |
| `projects` | read | Id, name, number, state and creation time |
| `instances` | read | Name, id, zone, status, machine type, internal and external IPs, whether it's Spot. `zone` filters |
| `start_instance` | write | Starts a stopped (`TERMINATED`) instance; compute billing resumes. Undo stops it |
| `stop_instance` | destructive | Shuts an instance down; an ephemeral external IP is released, and disks are still billed. Undo starts it |
| `reset_instance` | destructive | Hard-resets a running instance, with no clean shutdown |
| `run_services` | read | Name, region, URL, ingress, ready, latest ready and created revisions, and the traffic split. `region` filters (all regions by default) |
| `run_revisions` | read | A service's revisions: created, ready, images, min and max instances, and the share of traffic each one gets |
| `set_traffic` | destructive | Sends all traffic to one `revision` (or `"latest"`), or splits it with `traffic` entries that add up to 100 and may carry tags. The preview has Google validate the change without applying it. Undo restores the split it replaced |

Power actions and `set_traffic` answer "nothing to change" when the
instance or service is already as asked, and are refused when the state
doesn't fit (resetting a stopped instance). Health reports the project's
name and whether it's active.

**Security.** The key is read from the vault only to sign a short JWT
(RS256, standard library only), which is exchanged at
`oauth2.googleapis.com` for an access token kept in memory until shortly
before it expires. The key's own `token_uri` is never used. Project ids,
zones, regions and names are checked before any request, the token request
included, and escaped in paths. The client never follows a redirect to
another host or from https to http. Instance metadata (startup scripts,
SSH keys), service accounts and Cloud Run environment variables and secret
references are never shown; `set_traffic` sends the service back with
only its traffic changed.

**Notes.** Cloud Run lists across all regions with the `-` location; give a
`region` if your project restricts that. Projects come from Resource
Manager v1, which lists those the account can see.
