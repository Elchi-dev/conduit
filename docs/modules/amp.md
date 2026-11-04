# AMP

Game servers on CubeCoder [AMP](https://cubecoders.com/AMP): instances,
status, power, console commands and game updates.

**Setup.** Make an AMP user for Conduit without two-factor sign-in (Conduit
can't type a code), give it only the permissions it needs, and store its
password in the vault. Enter AMP's address: the ADS controller (the panel
that lists your instances), such as `https://amp.example.com`, or a
standalone instance. Conduit signs in with the username and password and
keeps the session, signing in again when AMP ends it. Calls for one instance
go through the controller's proxy, with a session of their own.

On a controller, name the `instance` by its name, friendly name or id (from
`instances`). On a standalone AMP, leave it out.

| Action | Risk | Notes |
| --- | --- | --- |
| `instances` | read | Every instance (not the controller itself) with game, state, CPU, memory and players. |
| `status` | read | Application state, uptime, CPU, memory and players. |
| `start` | write | Starts the instance if it's off, then its game server. Undo stops it. |
| `stop` | destructive | Stops the game server; the instance stays up. The preview says how many players are disconnected. Undo starts it. |
| `restart` | destructive | |
| `command` | destructive, sensitive | One console line (at most 500 characters). The server must be running. Sensitive because commands can carry passwords. |
| `update` | destructive | Updates the game server (SteamCMD or the game's updater). It stops meanwhile and mods may break. Can't be undone. |
| `console` | read, sensitive | Console lines since the last look. They hold IP addresses and anything typed into the console. |

**Security.** The password and session id travel in the request body; the
client refuses redirects to another host (a 307 or 308 would resend the
body). Instance names are checked before any call, and instance ids from
AMP are checked before they go into a proxy path. Errors are redacted.
