# Node-RED

Node-RED's flows by name, enabling and disabling a flow, and the installed
node modules, through the admin API.

**Setup.** Enter Node-RED's address, such as `http://nodered.local:1880`,
with `httpAdminRoot` if it's set (`http://host:1880/admin`). With
`adminAuth` in `settings.js`, enter a user's name and store its password in
the vault; Conduit signs in for a token and renews it. A setup with
`adminAuth.tokens` can use a `token` instead. Without `adminAuth`, leave all
three empty. Enabling and disabling flows needs a user with `*` or
`flows.write`. For a self-signed certificate, set `fingerprint`.

| Action | Risk | Notes |
| --- | --- | --- |
| `flows` | read | Each flow (tab): id, name, disabled and node count; each subflow's id, name and node count; how many config nodes there are. |
| `nodes` | read | Installed node modules: version, enabled, the node types they add and any load error. `search` filters by module or type. |
| `disable_flow` | destructive | Disables a flow: its nodes stop, and so do the automations it runs. The preview names the flow and its node count. Undo enables it. |
| `enable_flow` | write | Enables a disabled flow, so its nodes run again. Undo disables it. |

Enabling an enabled flow, or disabling a disabled one, reports "nothing to
change". After the change the flow is read again, so a change Node-RED
didn't keep is reported as such.

**Security.** Node settings are never returned: they can hold URLs, keys and
other credentials. Flows are read by id, label and type only; the update
sends the flow back to Node-RED as it came, with only `disabled` changed,
and the credentials file is never read. The password and token go only to
Node-RED, and the client won't follow a redirect to another host or from
https to http. Flow ids are checked before any request.

**Notes.** Deploying, editing or creating flows, and installing node
modules, aren't offered. Flow descriptions aren't returned.
