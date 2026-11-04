# Install

<p align="center"><img src="images/ori/hi.svg" width="120" alt="Ori waving hi"></p>

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

## Docker

The daemon image `ghcr.io/elchi-dev/conduitd` (amd64 and arm64) keeps
everything in `/data`:

```sh
docker run -d --name conduit -p 127.0.0.1:7600:7600 -v conduit:/data ghcr.io/elchi-dev/conduitd
docker logs conduit        # shows the setup token for the first sign-in
```

or `docker compose -f deploy/daemon/compose.yaml up -d`. Then open
http://127.0.0.1:7600.

- **Updates:** pull a newer image; the daemon's own updater is off in the
  container (`CONDUIT_MANAGED=container`).
- **Host names:** the daemon only answers to IP addresses, `localhost` and
  names you list in `CONDUIT_ALLOWED_HOSTS` (it refuses others to stop DNS
  rebinding). Behind a reverse proxy, set
  `-e CONDUIT_ALLOWED_HOSTS=conduit.example.com`.
- **Docker module:** to manage the host's containers, mount
  `/var/run/docker.sock` and give the container the socket's group
  (`--group-add <gid>`). Whoever controls Conduit then controls the host,
  so only do this when you mean to.
- **This computer:** inside a container the module sees the container, not
  the host. Run the daemon directly on the machine (the install script or
  the desktop app) to manage the host itself.
- **Health:** the image has a health check (`conduitd healthcheck`, which
  asks `/healthz`).
- **Backups:** `docker exec -e CONDUIT_BACKUP_PASSPHRASE='…' conduit conduitd backup -data /data -out /data/backup.cdb`,
  or use Settings, Backups ([backup.md](backup.md)).

## Android

Download `conduit-android-<version>.apk` from the release and open it (allow
installs from your browser or file manager when asked). The app checks for
new versions itself and installs them in place; every APK is signed with
the same key, so updates never need an uninstall.

An F-Droid repository (for F-Droid, Droid-ify or Neo Store) will follow
once it has a permanent web address.

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

Signed releases also carry `SHA256SUMS.sig`, an ed25519 signature of
`SHA256SUMS` by Conduit's release key. The install script checks it when
OpenSSL 3 is present (most Linux systems; on macOS install it with
Homebrew), so a mirror or a swapped download can't change a binary and its
checksum together; set `CONDUIT_REQUIRE_SIGNATURE=1` to refuse unsigned
releases. The Windows script checks the checksum only. To check by hand:

```sh
curl -fsSLO https://github.com/Elchi-dev/conduit/releases/latest/download/SHA256SUMS.sig
printf -- '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAcNW7YRR4O9dHz9WcIFMhaopG5Ky06OPh09axTD/Uj+c=\n-----END PUBLIC KEY-----\n' > conduit-release.pem
openssl base64 -d -A -in SHA256SUMS.sig -out SHA256SUMS.sig.bin
openssl pkeyutl -verify -pubin -inkey conduit-release.pem -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig.bin
```

They also carry `conduitd-release.json`, the ed25519-signed manifest the
daemon's own updater checks (see [protocol/updates.md](protocol/updates.md)).
`--version` takes only versions like `v1.2.3`, and a mirror
(`CONDUIT_DOWNLOAD_BASE`) must be https.

## Uninstall

`install.sh --uninstall` or `install.ps1 -Uninstall` (add `--hub` / `-Hub`
for the hub). Data isn't touched; delete the data folder above yourself if
you want it gone.
