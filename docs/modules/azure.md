# Azure

Azure subscriptions, resource groups and virtual machines with their power
state, starting, deallocating and restarting VMs, App Service apps (start,
stop, restart) and this month's costs, through Azure Resource Manager and a
service principal.

**Setup.** In the Azure portal, open Microsoft Entra ID, App registrations,
New registration, then Certificates & secrets, New client secret. Store the
secret's value in the vault and enter its `secret://` reference; a plain
value is refused. Enter the tenant (Directory) id and the application
(client) id from the registration's overview. On each subscription or
resource group Conduit should see, open Access control (IAM) and give the
app a role: *Reader* to watch, *Virtual Machine Contributor* and *Website
Contributor* to power VMs and apps, *Cost Management Reader* for costs.
Set `subscriptionId` so actions don't need one each time.

| Action | Risk | Notes |
| --- | --- | --- |
| `subscriptions` | read | Id, name and state of every subscription the app can see |
| `resource_groups` | read | Name, location and provisioning state |
| `vms` | read | Name, resource group, location, zones, size, OS type, power state (running, stopped, deallocated) and provisioning state. `resourceGroup` filters |
| `start_vm` | write | Starts a stopped or deallocated VM; compute billing resumes. Undo deallocates it again (when it was deallocated) |
| `deallocate_vm` | destructive | Shuts the VM down and releases its compute, which stops compute billing; its services go down, and a dynamic public IP is released. Undo starts it |
| `restart_vm` | destructive | Restarts a running VM |
| `webapps` | read | Web and function apps: name, resource group, kind, state, host name, enabled, HTTPS only, availability and plan |
| `start_webapp` | write | Starts a stopped app. Undo stops it again |
| `stop_webapp` | destructive | Stops an app; it stops answering, and its plan is still billed. Undo starts it |
| `restart_webapp` | destructive | Restarts a running app |
| `costs` | read, sensitive | Actual cost this month so far, in total and by service, in the billing currency |

Every power action has a preview showing the state before and after, and
answers "nothing to change" when the VM or app is already where it was
asked to go. Health reports how many subscriptions the app can see and the
state of the configured one.

**Security.** The client secret is read from the vault only to get an
access token, which is kept in memory until shortly before it expires.
Subscription ids, resource group, VM and app names are checked before any
request and escaped in paths; list pages are followed only on Azure's own
host. The client never follows a redirect to another host or from https to
http. VM custom data, user data and OS profiles, app settings, connection
strings and tags are never read.

**Notes.** Costs need Cost Management access on the subscription and may
lag a few hours behind usage. `start_vm` on a VM that was stopped (not
deallocated) gives no undo, since deallocating isn't the state it was in.
