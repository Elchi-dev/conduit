# Install

The desktop app (Windows, macOS, Linux) and the Android app are on the
[releases page](https://github.com/Elchi-dev/conduit/releases) and every
hub's Download page. To run only the daemon, or a hub, on a server or a
headless machine, use the install scripts below. They download the binary
for your system from the release, check it against the release's
`SHA256SUMS`, and refuse to install it if the checksum doesn't match.

Every hub serves the scripts at `/install.sh` and `/install.ps1`; the
examples use `https://hub.example.com`. You can also run them from a clone
(`scripts/install.sh`, `scripts/install.ps1`).

## Linux and macOS

```sh
curl -fsSL https://hub.example.com/install.sh | sh
```

Start the daemon at login as well:

```sh
curl -fsSL https://hub.example.com/install.sh | sh -s -- --service
```

| Option | What it does |
| --- | --- |
| `--hub` | Install the hub (`conduit-hub`) instead of the daemon |
| `--version v0.1.0` | Install that release instead of the latest |
| `--system` | Install to `/usr/local/bin` (with sudo if needed) instead of `~/.local/bin` |
| `--service` | Daemon only: a systemd user service on Linux (`systemctl --user status conduitd`), a launchd agent on macOS |
| `--uninstall` | Remove the binary and the service. Your data stays |
| `--help` | List the options |

`CONDUIT_DOWNLOAD_BASE` points the script at a mirror: a folder URL holding
the release files and `SHA256SUMS`.

On Linux a user service stops when you log out. To keep it running, enable
lingering once: `loginctl enable-linger $USER`.

## Windows

In PowerShell:

```powershell
irm https://hub.example.com/install.ps1 | iex
```

With options, for example to start the daemon at logon:

```powershell
& ([scriptblock]::Create((irm https://hub.example.com/install.ps1))) -Service
```

| Option | What it does |
| --- | --- |
| `-Hub` | Install the hub instead of the daemon |
| `-Version v0.1.0` | Install that release instead of the latest |
| `-Service` | Daemon only: a scheduled task that starts it at logon |
| `-Uninstall` | Remove the binary, the PATH entry and the scheduled task. Your data stays |

The binary goes to `%LOCALAPPDATA%\Conduit\bin`, which is added to your user
PATH.

## After installing

Open http://127.0.0.1:7600. The first start writes a one-time setup token,
which you need to create the owner account:

| System | Setup token |
| --- | --- |
| Linux | `~/.config/conduit/setup-token` |
| macOS | `~/Library/Application Support/conduit/setup-token` |
| Windows | `%APPDATA%\conduit\setup-token` |

It's also printed in the daemon's log. For a hub, continue with
[Self-hosting a hub](self-hosting/README.md).

## Check a download by hand

```sh
curl -fsSLO https://github.com/Elchi-dev/conduit/releases/latest/download/conduitd-linux-amd64
curl -fsSLO https://github.com/Elchi-dev/conduit/releases/latest/download/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS      # macOS: shasum -a 256 -c SHA256SUMS --ignore-missing
```

Signed releases also carry `conduitd-release.json`, the ed25519-signed
manifest the daemon's own updater checks (see
[protocol/updates.md](protocol/updates.md)).

## Uninstall

`install.sh --uninstall` or `install.ps1 -Uninstall` (add `--hub` / `-Hub`
for the hub). Data isn't touched; delete the data folder above yourself if
you want it gone.
