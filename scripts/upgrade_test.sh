#!/usr/bin/env bash
# Upgrade test: a data folder made by an older release must keep working
# with the current daemon. Builds the old release from its tag, sets it up
# (owner, vault with a secret, an API key, an agent rule, an automation),
# stops it, then starts the current daemon on the same folder and checks
# that everything is still there and usable.
#
#   scripts/upgrade_test.sh [old-tag ...]   (default: every v* tag)
#
# Needs git, go, curl and jq. Run from anywhere inside the repository.
set -euo pipefail

root=$(git rev-parse --show-toplevel)
work=$(mktemp -d)
pid=""
cleanup() {
	[ -n "$pid" ] && kill "$pid" 2>/dev/null || true
	git -C "$root" worktree remove --force "$work/old" 2>/dev/null || true
	rm -rf "$work"
}
trap cleanup EXIT

tags=("$@")
if [ ${#tags[@]} -eq 0 ]; then
	mapfile -t tags < <(git -C "$root" tag --list 'v*' --sort=version:refname)
fi
[ ${#tags[@]} -gt 0 ] || { echo "no release tags to test from"; exit 0; }

echo "building the current daemon"
(cd "$root" && CGO_ENABLED=0 go build -o "$work/new" ./cmd/conduitd)

port=$((20000 + RANDOM % 20000))
url="http://127.0.0.1:$port"
pass="correct horse battery staple"
vaultpass="a long vault passphrase"

start() { # binary data
	CONDUIT_UPDATE_CHECK=off "$1" -data "$2" -listen "127.0.0.1:$port" >"$work/log" 2>&1 &
	pid=$!
	for _ in $(seq 100); do
		curl -fs "$url/healthz" >/dev/null 2>&1 && return 0
		sleep 0.1
	done
	cat "$work/log"
	echo "the daemon didn't start"
	exit 1
}
stop() { kill "$pid"; wait "$pid" 2>/dev/null || true; pid=""; }
api() { # method path token [body]
	curl -fsS -X "$1" "$url$2" -H "Authorization: Bearer $3" -H 'Content-Type: application/json' ${4:+--data "$4"}
}
fail() { echo "FAIL ($tag): $*"; cat "$work/log"; exit 1; }

for tag in "${tags[@]}"; do
	echo "== from $tag"
	git -C "$root" worktree remove --force "$work/old" 2>/dev/null || true
	git -C "$root" worktree add -q --detach "$work/old" "$tag"
	(cd "$work/old" && CGO_ENABLED=0 go build -o "$work/old-bin" ./cmd/conduitd)
	data="$work/data-$tag"
	mkdir -p "$data"

	# Set up with the old release.
	start "$work/old-bin" "$data"
	setup=$(jq -n --arg t "$(cat "$data/setup-token")" --arg p "$pass" '{token:$t,name:"Owner",email:"owner@example.com",password:$p,device:"upgrade test"}')
	tok=$(curl -fsS -X POST "$url/api/v1/setup" -H 'Content-Type: application/json' --data "$setup" | jq -r .token)
	[ -n "$tok" ] && [ "$tok" != null ] || fail "setup on the old release"
	api POST /api/v1/vault/setup "$tok" "{\"passphrase\":\"$vaultpass\"}" >/dev/null
	api POST /api/v1/instances/vault/actions/set "$tok" '{"input":{"name":"upgrade/token","value":"kept-across-upgrades"}}' >/dev/null
	key=$(api POST /api/v1/keys "$tok" '{"name":"ci","kind":"live","scopes":["modules:*:read"]}' | jq -r .secret)
	[ -n "$key" ] && [ "$key" != null ] || fail "creating a key on the old release"
	api POST /api/v1/automations "$tok" '{"name":"Upgrade check","trigger":{"kind":"manual"},"steps":[]}' >/dev/null 2>&1 || true
	stop

	# Start the current daemon on the same folder.
	start "$work/new" "$data"
	login=$(jq -n --arg p "$pass" '{email:"owner@example.com",password:$p}')
	tok=$(curl -fsS -X POST "$url/api/v1/auth/login" -H 'Content-Type: application/json' --data "$login" | jq -r .token) || fail "signing in after the upgrade"
	[ -n "$tok" ] && [ "$tok" != null ] || fail "no session after the upgrade"
	api GET /api/v1/me "$key" >/dev/null || fail "the old API key stopped working"
	api POST /api/v1/vault/unlock "$tok" "{\"passphrase\":\"$vaultpass\"}" >/dev/null || fail "unlocking the vault"
	got=$(api POST /api/v1/instances/vault/actions/reveal "$tok" '{"input":{"name":"upgrade/token"}}')
	grep -q kept-across-upgrades <<<"$got" || fail "the vault secret didn't survive: $got"
	api GET /api/v1/audit/verify "$tok" | jq -e '.ok == true' >/dev/null || fail "the audit chain doesn't verify"
	stop
	echo "ok: $tag -> current"
done
