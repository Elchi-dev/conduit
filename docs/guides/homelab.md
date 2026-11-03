# Conduit for homelabs

You'll bring your hypervisor, storage, DNS blocker, media server and backups
into one place, sync settings between two machines, and light up a lamp
when something breaks.

## 1. Infrastructure

- **Proxmox VE**: API token (`user@pam!conduit`), and pin the certificate
  fingerprint instead of skipping certificate checks. Start, shut down and
  snapshot guests; snapshots undo.
- **TrueNAS**: API key; pools, datasets, alerts, snapshots and scrubs.
- **Docker** and **Server (SSH)** for everything else.
- **Tailscale**: devices, key expiry warnings, device tags.

## 2. Network and media

- **Pi-hole** or **AdGuard Home**: pause blocking for five minutes when a
  site breaks (undo resumes it), allow or block a domain.
- **Jellyfin**: who's watching what, recently added, scan libraries.
- **Home Assistant**: entities, scenes, lights; light changes undo.

## 3. Backups

- **Files and backups** runs restic or rsync jobs and warns when one is
  overdue or a disk is filling up.
- **Settings → Backups** keeps an encrypted copy of Conduit itself every
  day; point it at your NAS. See [backup.md](../backup.md).

## 4. Two machines, one setup

Running Conduit on a server and on your desktop? **Settings → Sync → Start
syncing** on one, **Join with a code** on the other. Pick the vault and
agent rules; they stay the same on both, directly on your network
(**Find computers on this network**) or through your hub.

## 5. A status light

**Ambient status** turns everything into one of four states (ok,
attention, down, stopped) and pushes it to a Home Assistant light, a
webhook, Discord or a Stream Deck button. Green means you can stop looking.
