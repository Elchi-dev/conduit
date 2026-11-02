# This computer

The machine running Conduit: resources, temperatures, processes, saved launch
profiles and game mode. One instance exists automatically.

## Settings

| Setting | Meaning |
| --- | --- |
| Launch profiles | Commands you start often, as `{name, command, args, dir}` |
| Games | Executable names, e.g. `cs2.exe`, `eldenring.exe` |
| Pause | Processes to pause while gaming (backup tools, indexers, sync clients) |
| Turn game mode on automatically | When a listed game starts; off again when it exits |

## Actions

| Action | Risk | Notes |
| --- | --- | --- |
| `overview` | read | CPU, memory, disks (real volumes over 1 GB), network, uptime |
| `processes` | read | Sorted by CPU or memory, with a name filter |
| `temperatures` | read | Where the OS exposes sensors (Linux hwmon, macOS SMC, some Windows drivers) |
| `profiles` | read | Saved launch profiles |
| `launch` | write | Starts a saved profile. Undo ends it. Agents can only pick a profile, never type a command. |
| `game_mode` | write | Pauses listed processes and announces game mode; undo turns it off. Dry run lists what would pause. |
| `kill` | destructive | By PID or exact name; terminate, or `force` to kill. Dry run lists matches. Conduit refuses to end itself. |

## Game mode

Turning game mode on suspends every running process named in **Pause** and
publishes `system.game_mode` with `{"on": true}`. Automations can react to that
event, for example pausing Docker containers or muting non-urgent
notifications. When **Games** are listed, Conduit checks every 10 seconds and
publishes `system.game.started` / `system.game.stopped`; with automatic game
mode it toggles itself.
