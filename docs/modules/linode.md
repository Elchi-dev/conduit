# Linode (Akamai Cloud)

Your Linode instances through the Linode API v4: status, region and plan,
power on, shut down and reboot; block storage volumes, cloud firewalls,
this month's network transfer, the account balance and invoices.

**Setup.** In Cloud Manager, open your profile, API Tokens, and create a
personal access token. Give it *Read Only* for Linodes, Volumes and
Firewalls to watch; *Read/Write* for Linodes to power instances; and
*Read Only* for Account to see the balance, invoices and transfer. Store
the token in the vault and enter its `secret://` reference; a plain token
is refused.

| Action | Risk | Notes |
| --- | --- | --- |
| `instances` | read | Status, region, plan (type), vCPUs, memory, disk, IPv4 and IPv6 |
| `volumes` | read | Size, status, region and the instance each is attached to |
| `firewalls` | read | Inbound and outbound policy, rules (action, protocol, ports, addresses) and the devices they protect. Read only: changing a firewall isn't offered |
| `network_transfer` | read | This month's pooled transfer: used, quota and billable overage in GB |
| `balance` | read, sensitive | The balance and what's accrued but not invoiced (USD). Never the billing address, email or card |
| `invoices` | read, sensitive | The latest `limit` invoices (1 to 100, 12 by default) with date, subtotal, tax and total |
| `power_on` | write | Boots an offline `instance`. Undo shuts it down again. Refused when it's already running. Preview shows the state change |
| `shutdown` | destructive | Shuts a running instance down: its services go down until it's powered on, and it's still billed. Undo boots it. Preview available |
| `reboot` | destructive | Reboots an instance; its services go down while it restarts. Preview available |

Health reports how many instances exist and how many aren't running.

**Security.** Instance ids are positive integers and limits are checked
before anything is sent. The token goes as a Bearer token; the client
follows redirects only within the same host and never from https to http,
and times out after 30 seconds. Billing data is marked sensitive, so it
never reaches the audit log or events. A read/write token can also delete
instances and change firewalls through the API; Conduit has no actions for
that, but treat the token as powerful.
