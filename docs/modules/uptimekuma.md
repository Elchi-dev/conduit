# Uptime Kuma

Which of your Uptime Kuma monitors are up, down, pending or in maintenance,
with response times and 24-hour uptime. Uptime Kuma has no API for changing
monitors, so this module only reads.

**Setup.** The address, and one or both of:

- **Status pages:** the slugs of public status pages (the part after
  `/status/`). No password needed; you see the monitors on those pages, with
  uptime.
- **API key:** Settings, API Keys in Uptime Kuma. Reads every monitor from
  `/metrics`, with response times. Stored in the vault.

| Action | Risk | Notes |
| --- | --- | --- |
| `monitors` | read | Down ones first. Combines both sources when both are set |

Health is *degraded* while any monitor is down, which makes this module's
lamp a summary of everything Uptime Kuma watches.
