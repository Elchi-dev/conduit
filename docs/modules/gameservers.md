# Game servers

See who's on the game servers you host and run their console: Minecraft
(Java edition) and Source/Valve games, plus any game that answers Valve's
A2S queries (CS2, TF2, Garry's Mod, Rust, ARK, Valheim and many more).

**Setup.** Add each server with its kind (`minecraft` or `source`), host and
port (defaults 25565 and 27015). For commands, turn on RCON on the server and
store its password in the vault:

- Minecraft: in `server.properties`, set `enable-rcon=true`,
  `rcon.password=…` and `rcon.port=25575`.
- Source games: start the server with `+rcon_password …`; RCON uses the game
  port over TCP.

Without an RCON password the module only watches.

| Action | Risk | Notes |
| --- | --- | --- |
| `status` | read | For one server or all: online, players, maximum, version, message of the day or server name, map, latency |
| `players` | read | Minecraft lists the sample the server shares; Source games list names, scores and time connected |
| `say` | write | A one-line chat message to everyone (RCON) |
| `whitelist_add` / `whitelist_remove` | write | Minecraft. Each undoes the other |
| `command` | destructive | Any console command, one line, through RCON. It can't be undone, so the default rules ask before an agent runs one |

Health is ok when every server answers, degraded when some do.

**Security.** RCON sends the password and commands unencrypted, as the
protocol has no encryption: use it on your own network or over a VPN, never
across the internet. Status queries need no password. Host names and
commands are checked; commands can't span lines.
