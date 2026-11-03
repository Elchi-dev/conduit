# Command-line client

`conduit` talks to a daemon's API with an API key: run actions, follow live
events, read the audit log and approvals from a terminal or a script. It is
a program like any other, so everything it does goes through your agent and
key rules and lands in the audit log.

## Install

```sh
curl -fsSL https://<your hub>/install.sh | sh -s -- --cli   # Linux, macOS
```

Or download `conduit-<os>-<arch>` from the
[release](https://github.com/Elchi-dev/conduit/releases) and put it on your
PATH, or build it: `make cli` (writes `bin/conduit`).

## Sign in

Create a key in Conduit under **API keys**: a live key for scripts, an agent
key for AI tools. Give it only the scopes it needs (`modules:*:read`,
`actions:<module>:invoke`, `audit:*:read`, `approvals:*:read`,
`events:*:read`…). Then:

```sh
conduit login
# Conduit address [http://127.0.0.1:7600]:
# API key: cdt_live_…
conduit whoami
```

`login` checks the key and saves it to `~/.config/conduit/config.json`
(`%AppData%\conduit\config.json` on Windows), readable only by you. Several
daemons: `conduit login --profile work`, then `--profile work` on any
command or `CONDUIT_PROFILE=work`. Without a saved profile, `--url` /
`CONDUIT_URL` and `--key` / `CONDUIT_API_KEY` work too (handy in CI).
`conduit logout` forgets the saved key; revoke it in Conduit to stop it
working.

## Commands

Every command takes `--json` for machine-readable output, `--url`, `--key`
and `--profile`, and `--help`.

| Command | What it does |
| --- | --- |
| `conduit modules` | Installed modules |
| `conduit instances [--module docker]` | Set-up instances; actions run on these |
| `conduit actions <instance>` | An instance's actions, their risk, and whether they undo or preview |
| `conduit run <instance> <action> [key=value …]` | Run an action |
| `conduit approvals [--pending]` | Approvals, newest first |
| `conduit approve <id>` / `deny <id>` | Decide (people only: keys get "not allowed") |
| `conduit audit [--module m] [--limit n] [--follow]` | The audit log; `--follow` prints new entries as they happen |
| `conduit undo <seq>` | Undo an audited action |
| `conduit events [--type action.]` | Follow live events; reconnects by itself |
| `conduit vault list` | Secret names (values are never shown) |
| `conduit automations list` / `run <id>` | List or start automations |
| `conduit panic [--yes]` | Pull the emergency stop (the key that pulls it is revoked) |
| `conduit completion bash\|zsh\|fish\|powershell` | Shell completion |
| `conduit version` | The client's version |

An instance can be named by its id, by its module when there is only one
instance of it (`conduit run vault list`), or by its name.

### Inputs

`key=value` pairs build the action's input. Numbers, `true`, `false`,
`null`, and values that start with `{`, `[` or `"` are read as JSON;
everything else is a string (`zip=0123` stays a string). `key:=json` always
reads JSON. Dots nest: `limits.memory=512` becomes `{"limits":{"memory":512}}`.

```sh
conduit run docker restart container=web
conduit run web check url=https://example.com timeout=10
conduit run notes write name=standup.md text="$(cat standup.md)"
conduit run kubernetes scale deployment=api replicas=3 --dry-run   # preview only
conduit run servers service_restart --input request.json
echo '{"message":"Deploy done"}' | conduit run discord send --input -
```

`--dry-run` asks for a preview without changing anything (for actions that
support it). `--wait` waits for an approval instead of returning at once.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Done |
| 1 | Error (unreachable daemon, module error, bad key…) |
| 2 | Usage error |
| 3 | Waiting for approval: a person has to approve it; it then runs by itself |
| 4 | Not allowed by the rules |

## Scripting

```sh
# Restart a service and fail the CI job unless it ran.
conduit run servers service_restart unit=api --json > out.json
case $? in
  0) jq -r '.audit.seq' out.json ;;
  3) echo "waiting for approval $(jq -r .approval.id out.json)"; exit 1 ;;
  *) exit 1 ;;
esac

# Every failing action in the last 100 audit entries.
conduit audit --limit 100 --json | jq -r '.[] | select(.status=="error") | "\(.seq) \(.module).\(.action): \(.error)"'

# React to events (one JSON object per line).
conduit events --type web.down --json | while read -r ev; do
  echo "$ev" | jq -r '.data.name' | xargs -I{} notify-send "{} is down"
done
```

## Shell completion

```sh
conduit completion bash > ~/.local/share/bash-completion/completions/conduit
conduit completion zsh  > "${fpath[1]}/_conduit"
conduit completion fish > ~/.config/fish/completions/conduit.fish
conduit completion powershell >> $PROFILE
```

Instance names complete by asking the daemon, so log in first.
