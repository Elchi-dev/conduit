#!/bin/sh
# Builds an F-Droid repository (index-v1.jar, entry.jar, index-v2.json, …)
# around Conduit APKs, so the F-Droid app (or Droid-ify, Neo Store) can
# install and update Conduit. The repository is static files: the release
# workflow uploads them next to the APK, so the repository address is the
# release download URL.
#
# Usage: scripts/fdroid-repo.sh <out-dir> <repo-url> <apk>...
# Environment: FDROID_KEYSTORE (path), FDROID_KEYSTORE_PASS, FDROID_KEY_ALIAS,
# FDROID_KEY_PASS. Needs fdroidserver (pip install fdroidserver) and the
# Android build tools (apksigner) on PATH or in $ANDROID_HOME.
set -eu

out=$1
url=$2
shift 2
: "${FDROID_KEYSTORE:?set FDROID_KEYSTORE}"
: "${FDROID_KEYSTORE_PASS:?}" "${FDROID_KEY_ALIAS:?}" "${FDROID_KEY_PASS:?}"

here=$(cd "$(dirname "$0")" && pwd)
rm -rf "$out"
mkdir -p "$out/repo" "$out/metadata"
for apk in "$@"; do
  cp "$apk" "$out/repo/"
done
ks=$(cd "$(dirname "$FDROID_KEYSTORE")" && pwd)/$(basename "$FDROID_KEYSTORE")

if [ -z "${APKSIGNER:-}" ]; then
  APKSIGNER=$(command -v apksigner || true)
  if [ -z "$APKSIGNER" ] && [ -n "${ANDROID_HOME:-}" ]; then
    APKSIGNER=$(ls "$ANDROID_HOME"/build-tools/*/apksigner 2>/dev/null | sort -V | tail -1)
  fi
fi
[ -n "$APKSIGNER" ] || { echo "apksigner not found" >&2; exit 1; }

cat > "$out/config.yml" <<CFG
repo_url: $url
repo_name: Conduit
repo_description: >-
  Conduit for Android, published by its developers. Add this repository to
  F-Droid to install Conduit and get its updates.
repo_keyalias: $FDROID_KEY_ALIAS
keystore: $ks
keystorepass: $FDROID_KEYSTORE_PASS
keypass: $FDROID_KEY_PASS
keydname: CN=Conduit
apksigner: $APKSIGNER
CFG
chmod 600 "$out/config.yml"

cat > "$out/metadata/dev.elchi.conduit.yml" <<META
Categories:
  - System
  - Connectivity
AuthorName: Conduit
WebSite: https://github.com/Elchi-dev/conduit
SourceCode: https://github.com/Elchi-dev/conduit
IssueTracker: https://github.com/Elchi-dev/conduit/issues
Changelog: https://github.com/Elchi-dev/conduit/releases
Name: Conduit
Summary: Your servers, secrets, mail and home in one place, with AI agents under your rules
Description: |-
  Conduit is the phone side of a Conduit daemon running on your computer or
  server. Pair it by scanning a QR code, then approve what agents want to do
  (with your fingerprint), see what changed, undo it, or pull the emergency
  stop, from anywhere. Traffic is end-to-end encrypted, on your network or
  through a hub that only sees ciphertext.
META

if [ -f "$here/../apps/desktop/src-tauri/icons/icon.png" ]; then
  mkdir -p "$out/repo/icons"
  cp "$here/../apps/desktop/src-tauri/icons/icon.png" "$out/repo/icons/icon.png"
fi

(cd "$out" && fdroid update --create-metadata --pretty)
rm -f "$out/config.yml"

# Fail when the APK didn't make it into the index (bad signature, say).
python3 - "$out/repo/index-v2.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
pkgs = d.get("packages", {})
if "dev.elchi.conduit" not in pkgs:
    sys.exit("dev.elchi.conduit isn't in the index; check the warnings above")
for v in pkgs["dev.elchi.conduit"]["versions"].values():
    print("indexed", v["file"]["name"], v["manifest"]["versionName"])
PY
