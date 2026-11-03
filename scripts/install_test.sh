#!/bin/sh
# Tests install.sh against a fake release served from a local folder.
# Run from the repository root: sh scripts/install_test.sh
set -eu

ROOT="$(pwd)"
WORK="$(mktemp -d)"
PORT="${PORT:-8765}"
trap 'kill "$SRV" 2>/dev/null || true; rm -rf "$WORK"' EXIT INT TERM

case "$(uname -s)" in Linux) OS=linux ;; Darwin) OS=darwin ;; esac
case "$(uname -m)" in x86_64 | amd64) ARCH=amd64 ;; *) ARCH=arm64 ;; esac

mkdir -p "$WORK/rel" "$WORK/home"
CGO_ENABLED=0 go build -o "$WORK/rel/conduitd-$OS-$ARCH" ./cmd/conduitd
if command -v sha256sum >/dev/null 2>&1; then
	(cd "$WORK/rel" && sha256sum "conduitd-$OS-$ARCH" >SHA256SUMS)
else
	(cd "$WORK/rel" && shasum -a 256 "conduitd-$OS-$ARCH" >SHA256SUMS)
fi
(cd "$WORK/rel" && exec python3 -m http.server "$PORT" --bind 127.0.0.1 >/dev/null 2>&1) &
SRV=$!
i=0
until curl -fs "http://127.0.0.1:$PORT/SHA256SUMS" >/dev/null 2>&1; do
	i=$((i + 1))
	[ $i -lt 50 ] || { echo "FAIL: fake release server didn't start"; exit 1; }
	sleep 0.1
done

run() { HOME="$WORK/home" CONDUIT_DOWNLOAD_BASE="http://127.0.0.1:$PORT" sh "$ROOT/scripts/install.sh" "$@"; }
BIN="$WORK/home/.local/bin/conduitd"

sh "$ROOT/scripts/install.sh" --help | grep -q -- "--uninstall" || { echo "FAIL: --help"; exit 1; }

run >/dev/null
"$BIN" version | grep -q '^conduitd ' || { echo "FAIL: installed binary doesn't run"; exit 1; }
echo "ok   install"

run >/dev/null # idempotent
"$BIN" version >/dev/null || { echo "FAIL: second install"; exit 1; }
echo "ok   install again"

run --uninstall >/dev/null
[ ! -e "$BIN" ] || { echo "FAIL: uninstall left the binary"; exit 1; }
echo "ok   uninstall"

# A signed SHA256SUMS: a good signature installs, a bad one is refused.
if command -v openssl >/dev/null 2>&1 && openssl version | grep -q '^OpenSSL [3-9]'; then
	openssl genpkey -algorithm ed25519 -out "$WORK/k.pem" 2>/dev/null
	PUB=$(openssl pkey -in "$WORK/k.pem" -pubout | grep -v -- '-----')
	openssl pkeyutl -sign -inkey "$WORK/k.pem" -rawin -in "$WORK/rel/SHA256SUMS" -out "$WORK/sig.bin"
	openssl base64 -A -in "$WORK/sig.bin" -out "$WORK/rel/SHA256SUMS.sig"
	CONDUIT_RELEASE_PUBKEY="$PUB" run >"$WORK/out" 2>&1 || { echo "FAIL: signed release refused"; cat "$WORK/out"; exit 1; }
	grep -q "Signature OK" "$WORK/out" || { echo "FAIL: signature not checked"; cat "$WORK/out"; exit 1; }
	echo "ok   signature checked"
	openssl genpkey -algorithm ed25519 -out "$WORK/other.pem" 2>/dev/null
	OTHER=$(openssl pkey -in "$WORK/other.pem" -pubout | grep -v -- '-----')
	if CONDUIT_RELEASE_PUBKEY="$OTHER" run >"$WORK/out" 2>&1; then
		echo "FAIL: a signature from another key was accepted"
		exit 1
	fi
	echo "ok   wrong signature refused"
	rm -f "$WORK/rel/SHA256SUMS.sig"
	run --uninstall >/dev/null
fi

# A tampered binary must be refused and nothing installed.
printf 'x' >>"$WORK/rel/conduitd-$OS-$ARCH"
if run >"$WORK/out" 2>&1; then
	echo "FAIL: a checksum mismatch was installed"
	exit 1
fi
grep -q "checksum mismatch" "$WORK/out" || { echo "FAIL: no mismatch message"; cat "$WORK/out"; exit 1; }
[ ! -e "$BIN" ] || { echo "FAIL: binary installed despite mismatch"; exit 1; }
echo "ok   checksum mismatch refused"

# A missing entry is refused too.
: >"$WORK/rel/SHA256SUMS"
if run >/dev/null 2>&1; then
	echo "FAIL: missing checksum entry accepted"
	exit 1
fi
echo "ok   missing checksum refused"

for v in nonsense v1 'v1/../../evil/releases/download/v1'; do
	if run --version "$v" >/dev/null 2>&1; then
		echo "FAIL: bad version $v accepted"
		exit 1
	fi
done
if HOME="$WORK/home" CONDUIT_DOWNLOAD_BASE="http://mirror.example" sh "$ROOT/scripts/install.sh" >/dev/null 2>&1; then
	echo "FAIL: plain-http mirror accepted"
	exit 1
fi
echo "ok   bad version refused"
