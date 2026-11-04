# OVHcloud

OVHcloud dedicated servers, VPS and Public Cloud instances: state, start,
stop and reboot; Public Cloud projects; and the account's domains. Works
with OVHcloud Europe, Canada and US, Kimsufi and So you Start.

**Setup.** Create an application and a consumer key at your endpoint's
token page (for Europe, `https://eu.api.ovh.com/createToken/`), limited to
the calls Conduit makes, for example `GET /*` to watch and
`POST /vps/*`, `POST /dedicated/server/*/reboot` and
`POST /cloud/project/*/instance/*` to power things. Enter the application
key as it is; store the application secret and the consumer key in the
vault and enter their `secret://` references (plain values are refused).
Pick the `endpoint` the account lives on (`ovh-eu` by default).

| Action | Risk | Notes |
| --- | --- | --- |
| `dedicated_servers` | read | Name, IP, reverse, datacenter, state, power state, range, OS and monitoring |
| `reboot_dedicated` | destructive | Hard-reboots a dedicated server (power cycle) |
| `vps` | read | Name, display name, state, zone, model, cores, memory and offer |
| `start_vps` | write | Starts a stopped VPS. Undo stops it |
| `stop_vps` | destructive | Stops a running VPS; it's still billed. Undo starts it |
| `reboot_vps` | destructive | Reboots a running VPS |
| `cloud_projects` | read | Project id, name, description, status and creation date |
| `cloud_instances` | read | A project's instances: id, name, status, region, flavor, plan and addresses |
| `start_instance` | write | Starts a stopped (`SHUTOFF`) instance. Undo stops it |
| `stop_instance` | destructive | Shuts an instance down; a stopped instance is still billed. Undo starts it |
| `reboot_instance` | destructive | Soft-reboots an active instance |
| `domains` | read | The domain names on the account |

Power actions have previews, answer "nothing to change" when the server is
already in the asked state, and are refused when the state doesn't fit.
Health checks the consumer key: validated, and when it expires (degraded in
its last week).

**Security.** Every request is signed as OVHcloud requires (SHA-1 over the
application secret, consumer key, method, URL, body and the server's time,
which is asked once). The secrets are read from the vault for each request
and never shown. Names and ids are checked before any request and escaped
in paths; the client never follows a redirect to another host or from
https to http. Root passwords, SSH keys and contact details are never read.

**Notes.** Listings look up the first 50 servers or projects of each kind
and say so when there are more. Dedicated servers have no start or stop in
the API, only reboot.
