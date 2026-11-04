# Network UPS Tools

UPSes through NUT's `upsd`, over its own TCP protocol (port 3493): every UPS
upsd serves with its status, battery charge and runtime, load and input
voltage; one UPS in detail; the alarms that need attention; a UPS's
variables and instant commands; and turning the beeper off or on.

**Setup.** Enter upsd's host (with `:port` when it isn't 3493). Reading
needs no login. For the beeper actions, add a user to `upsd.users` that may
run only those commands, and store its password in the vault:

```
[conduit]
    password = …
    instcmds = beeper.disable beeper.enable
```

`tls` is `auto` by default: the module asks for STARTTLS and uses it when
upsd offers it (`CERTFILE` in `upsd.conf`), otherwise it talks plain TCP.
Set it to `require` to refuse plain TCP, which matters when a password is
set: in `auto` mode someone on the path could answer that TLS isn't
available and read the password. upsd's certificate is usually self-signed:
enter its SHA-256 `fingerprint` (that also implies `require`).

| Action | Risk | Notes |
| --- | --- | --- |
| `upses` | read | Each UPS with its status flags, on battery, battery charge, runtime, load, input voltage and watts (from `ups.realpower`, or estimated from the nominal power and load). |
| `status` | read | One `ups` (by name, or `ups@host`; may be left out when upsd serves one): everything above plus battery and output voltage, frequency, temperature, low-battery marks, make, model, serial, driver, beeper, last self-test, battery date, and its alarms. |
| `alarms` | read | Across all UPSes: forced shutdown, low battery (or charge at its low mark), overload and output off (critical); on battery with minutes left, replace battery, bypass, driver alarms and failed self-tests (warning); stale or disconnected drivers. |
| `variables` | read | All of a UPS's variables, as `upsc` shows them. |
| `commands` | read | The instant commands the driver offers, each marked with whether Conduit will send it (only the beeper ones). |
| `beeper_disable` | write | Silences the UPS's alarm (`beeper.disable`). The plan shows `ups.beeper.status` before and after; nothing is sent when it's already disabled. Undo is `beeper_enable`. |
| `beeper_enable` | write | Turns the alarm back on (`beeper.enable`). Undo is `beeper_disable`. |

Health is `degraded` while any UPS has an alarm or stale data.

**No shutdown commands.** The module has no generic instant-command action.
It sends only `beeper.disable` and `beeper.enable`, and refuses anything
else by name, including `shutdown.*`, `load.off`, `load.on`, outlet,
calibration and battery-test commands, even when they're passed to a
beeper action. Cutting power belongs to `upsmon`. It also never sends
`LOGIN`, which would register it with upsd as a client that a primary
upsmon waits for before powering off.

**Security.** UPS names are checked (letters, digits, `.`, `_`, `+`, `-`)
before they go into a request line, and nothing with a line break is ever
sent, so input can't add commands. The username and password are quoted and
sent only for the beeper actions, after STARTTLS when it's on. Each call
uses its own connection with a 10-second deadline, lines are limited to
4 KB and lists to 5,000 entries.
