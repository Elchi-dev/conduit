# Streamer.bot

Streamer.bot on your streaming PC: list its actions, run one with
arguments, and read its global variables.

**Setup.** In Streamer.bot, *Servers/Clients*, turn on the **HTTP Server**
(default `http://127.0.0.1:7474`) and enter its address. For global
variables also turn on the **WebSocket Server** (default
`ws://127.0.0.1:8080/`), enter its address, and if you enable its
authentication, store the password in the vault. The module is optional:
the HTTP server alone is enough for listing and running actions.

| Action | Risk | Notes |
| --- | --- | --- |
| `actions` | read | Actions with their id, group, enabled and subaction count; `group` narrows it. |
| `run_action` | destructive | Runs one action by `action` name (exact) or `id`, with optional `args` (up to 20 named text, number or true/false values the action reads as `%name%`). Unknown, disabled or ambiguous names are refused before anything runs; the preview names the action, its group and the arguments. |
| `globals` | read, sensitive | Persisted (default) or temporary (`persisted: false`) global variables with their values and last write. Sensitive: they often hold viewer names, counters and tokens. |

`run_action` is destructive because an action can do anything Streamer.bot
can: post in chat, switch scenes, start a raid, play sounds, call other
programs. Approve it per action if you allow an agent to use it.

**Security.** Streamer.bot's HTTP server has no authentication: anyone who
can reach it can run your actions. Keep it bound to `127.0.0.1` or your
LAN behind a firewall, and run Conduit on the same PC or reach it through
one of Conduit's networks. The WebSocket password is sent as a
salted challenge response, never in clear. Redirects to another host are
refused.
