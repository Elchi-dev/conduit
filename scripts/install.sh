#!/bin/sh
# Install Conduit's daemon (conduitd) or hub (conduit-hub) on Linux or macOS.
#
#   curl -fsSL https://<hub>/install.sh | sh
#   curl -fsSL https://<hub>/install.sh | sh -s -- --service
#   sh install.sh --help
#
# Downloads the binary for this system from the GitHub release, checks it
# against the release's SHA256SUMS and refuses to install on a mismatch.
# Docs: docs/install.md.
set -eu

REPO="Elchi-dev/conduit"
VERSION="latest"
NAME="conduitd"
SYSTEM=0
SERVICE=0
UNINSTALL=0

usage() {
	cat <<'EOF'
Install Conduit.

Usage: install.sh [options]

  --hub              install the hub (conduit-hub) instead of the daemon
  --version vX.Y.Z   install this release instead of the latest
  --system           install to /usr/local/bin (uses sudo if needed)
                     instead of ~/.local/bin
  --service          start the daemon at login: a systemd user service on
                     Linux, a launchd agent on macOS (daemon only)
  --uninstall        remove the binary and the service; your data stays
  -h, --help         show this help

Environment:
  CONDUIT_DOWNLOAD_BASE  folder URL with the release files (a mirror);
                         default: the GitHub release
EOF
}

say() { printf '%s\n' "$*"; }
fail() {
	printf 'install.sh: %s\n' "$*" >&2
	exit 1
}

while [ $# -gt 0 ]; do
	case "$1" in
	--hub) NAME="conduit-hub" ;;
	--version)
		[ $# -ge 2 ] || fail "--version needs a value, e.g. --version v0.1.0"
		VERSION="$2"
		shift
		;;
	--version=*) VERSION="${1#--version=}" ;;
	--system) SYSTEM=1 ;;
	--service) SERVICE=1 ;;
	--uninstall) UNINSTALL=1 ;;
	-h | --help)
		usage
		exit 0
		;;
	*) fail "unknown option $1 (see --help)" ;;
	esac
	shift
done

case "$VERSION" in
latest | v[0-9]*) ;;
*) fail "versions look like v0.1.0" ;;
esac
if [ "$SERVICE" = 1 ] && [ "$NAME" = "conduit-hub" ]; then
	fail "--service is for the daemon; run the hub as described in docs/self-hosting"
fi

case "$(uname -s)" in
Linux) OS=linux ;;
Darwin) OS=darwin ;;
*) fail "this script is for Linux and macOS; on Windows use install.ps1" ;;
esac
case "$(uname -m)" in
x86_64 | amd64) ARCH=amd64 ;;
aarch64 | arm64) ARCH=arm64 ;;
*) fail "no release for $(uname -m); build from source (see README.md)" ;;
esac

if [ "$SYSTEM" = 1 ]; then
	BIN_DIR="/usr/local/bin"
else
	BIN_DIR="$HOME/.local/bin"
fi
TARGET="$BIN_DIR/$NAME"

# run_priv runs a command, with sudo when the folder isn't writable.
run_priv() {
	if [ -w "$BIN_DIR" ] || { [ ! -e "$BIN_DIR" ] && [ "$SYSTEM" = 0 ]; }; then
		"$@"
	elif command -v sudo >/dev/null 2>&1; then
		sudo "$@"
	else
		fail "$BIN_DIR isn't writable and sudo isn't available"
	fi
}

UNIT_DIR="$HOME/.config/systemd/user"
UNIT="$UNIT_DIR/conduitd.service"
PLIST="$HOME/Library/LaunchAgents/dev.conduit.conduitd.plist"

remove_service() {
	if [ "$OS" = linux ] && [ -f "$UNIT" ]; then
		systemctl --user disable --now conduitd.service >/dev/null 2>&1 || true
		rm -f "$UNIT"
		systemctl --user daemon-reload >/dev/null 2>&1 || true
		say "Removed the conduitd user service."
	fi
	if [ "$OS" = darwin ] && [ -f "$PLIST" ]; then
		launchctl unload "$PLIST" >/dev/null 2>&1 || true
		rm -f "$PLIST"
		say "Removed the conduitd launch agent."
	fi
}

if [ "$UNINSTALL" = 1 ]; then
	[ "$NAME" = conduitd ] && remove_service
	if [ -e "$TARGET" ]; then
		run_priv rm -f "$TARGET"
		say "Removed $TARGET."
	else
		say "$TARGET isn't installed."
	fi
	say "Your data was left in place."
	exit 0
fi

if command -v curl >/dev/null 2>&1; then
	fetch() { curl -fsSL --retry 2 -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
	fetch() { wget -q -O "$2" "$1"; }
else
	fail "needs curl or wget"
fi
if command -v sha256sum >/dev/null 2>&1; then
	sha256() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
	sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
	fail "needs sha256sum or shasum to check the download"
fi

if [ -n "${CONDUIT_DOWNLOAD_BASE:-}" ]; then
	BASE="${CONDUIT_DOWNLOAD_BASE%/}"
elif [ "$VERSION" = latest ]; then
	BASE="https://github.com/$REPO/releases/latest/download"
else
	BASE="https://github.com/$REPO/releases/download/$VERSION"
fi
ASSET="$NAME-$OS-$ARCH"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT INT TERM

say "Downloading $ASSET ($VERSION)…"
fetch "$BASE/$ASSET" "$TMP/$ASSET" || fail "couldn't download $BASE/$ASSET"
fetch "$BASE/SHA256SUMS" "$TMP/SHA256SUMS" || fail "couldn't download $BASE/SHA256SUMS"

WANT="$(awk -v f="$ASSET" '{ n = $2; sub(/^\*/, "", n); if (n == f) print $1 }' "$TMP/SHA256SUMS")"
[ -n "$WANT" ] || fail "SHA256SUMS has no entry for $ASSET"
GOT="$(sha256 "$TMP/$ASSET")"
if [ "$WANT" != "$GOT" ]; then
	fail "checksum mismatch for $ASSET (expected $WANT, got $GOT); nothing was installed"
fi
say "Checksum OK."

chmod 0755 "$TMP/$ASSET"
if [ "$OS" = darwin ]; then
	xattr -d com.apple.quarantine "$TMP/$ASSET" >/dev/null 2>&1 || true
fi
run_priv mkdir -p "$BIN_DIR"
run_priv mv -f "$TMP/$ASSET" "$TARGET"
say "Installed $TARGET."

case ":$PATH:" in
*":$BIN_DIR:"*) ;;
*) say "Add $BIN_DIR to your PATH to run $NAME by name." ;;
esac

if [ "$NAME" = conduit-hub ]; then
	say "Configure and run the hub as described in docs/self-hosting (https://github.com/$REPO/tree/main/docs/self-hosting)."
	exit 0
fi

if [ "$OS" = darwin ]; then
	DATA="$HOME/Library/Application Support/conduit"
else
	DATA="${XDG_CONFIG_HOME:-$HOME/.config}/conduit"
fi

if [ "$SERVICE" = 1 ]; then
	if [ "$OS" = linux ]; then
		command -v systemctl >/dev/null 2>&1 || fail "--service needs systemd; start $TARGET yourself instead"
		mkdir -p "$UNIT_DIR"
		cat >"$UNIT" <<EOF
[Unit]
Description=Conduit daemon
After=network-online.target

[Service]
ExecStart=$TARGET
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
EOF
		systemctl --user daemon-reload
		systemctl --user enable --now conduitd.service >/dev/null
		systemctl --user restart conduitd.service
		say "conduitd runs as a user service (systemctl --user status conduitd)."
		say "To keep it running after you log out: loginctl enable-linger $(id -un)"
	else
		mkdir -p "$(dirname "$PLIST")"
		cat >"$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>dev.conduit.conduitd</string>
  <key>ProgramArguments</key><array><string>$TARGET</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
</plist>
EOF
		launchctl unload "$PLIST" >/dev/null 2>&1 || true
		launchctl load "$PLIST"
		say "conduitd starts at login (launchctl list | grep conduit)."
	fi
	say ""
	say "Open http://127.0.0.1:7600 to set it up."
else
	say ""
	say "Start it with: $TARGET"
	say "Then open http://127.0.0.1:7600 to set it up."
fi
say "The first start writes a one-time setup token to:"
say "  $DATA/setup-token"
