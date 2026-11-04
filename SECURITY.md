# Security

<p align="center"><img src="docs/images/ori/reading.svg" width="120" alt="Ori looking closely through a magnifying glass"></p>

Conduit holds the keys to what you run and lets AI agents act on it. This
page says what stands between an agent and your systems, what does not, and
how to report a problem.

## Reporting

Please do not open a public issue for a security problem. Use GitHub's
private vulnerability reporting on this repository (Security, Report a
vulnerability), or write to github@elchi.dev. Include the version
(`conduitd version`), your system and the steps. You get an answer within
a week.

## What Conduit protects against

**Agents doing more than you allow.** Every call, from the app, an API key,
an agent over MCP or an automation, takes the same path:

```
caller ──► policy engine ──► approval ──► module action ──► audit log
            allow, ask, deny   a person      or a dry run      hash chain, undo
```

There is no other way in. Agents never get more than the person they act
for, and only people decide approvals, change policy, create keys or lift
the emergency stop. The emergency stop denies every agent, key and
automation at once, even for reads, revokes agent keys and locks the vault.

**Risky actions slipping through.** Every action declares a risk level:
`read`, `write` or `destructive`. Deleting, restarting, revealing a secret,
posting publicly, moving money, changing access and silencing alerts are
destructive and wait for your approval unless you chose full autonomy. A
test (`internal/daemon/risk_lint_test.go`) checks every action's name and
undo against these rules.

**Approving something other than what runs.** Risky actions show a preview
of the exact change before they run, and the approval carries it. Refunds,
payments, order changes and newsletter sends take the values their preview
showed and refuse to run if anything changed in between. Locks, doors,
alarms, cameras and heating go through their own destructive action.

**Edits to the record.** The audit log is append-only, and each entry's
SHA-256 hash covers the previous entry's hash. Verification names the first
entry that was changed or whose predecessor was removed. Inputs and outputs
of sensitive actions are redacted there and in events and approvals; only
people who decide approvals see the full previews.

**Leaked secrets.** The vault seals every secret with XChaCha20-Poly1305
under a random data key, wrapped by a key derived from your passphrase with
Argon2id ([docs/architecture/vault.md](docs/architecture/vault.md)).
Modules see credentials only as `secret://` references, and the engine
resolves only the references in that module instance's own settings.
Agents never see a value unless a person approves it. Leak watch finds
vault values in text and folders and reports them by name, never by value.
Teams can restrict folders such as `finance/` to certain roles and people.

**Modules you don't fully trust.** Modules from a hub or from someone else
run as WebAssembly with no files, no environment and no sockets; HTTPS goes
only to hosts you granted, never to private addresses
([docs/protocol/sandbox.md](docs/protocol/sandbox.md)). The author's
signature is checked and their key pinned on first install. Built-in
modules talk only to the host you configured and refuse redirects to
others.

**Tampered updates.** Releases are signed: daemon and hub downloads with an
ed25519 release key, desktop updates with minisign, the Android APK with its
keystore ([docs/protocol/updates.md](docs/protocol/updates.md)). The
installers check `SHA256SUMS.sig` before they install, and the daemon rolls
back an update that doesn't start.

**Other websites and networks.** The daemon checks the Host header against
DNS rebinding, cookie-authenticated changes need a same-origin request, and
sign-ins are rate limited. Remote access through a hub is end to end
encrypted with fresh session keys, so the hub sees only ciphertext and
can't replay a session.

**Backups in the wrong hands.** A backup is one file encrypted with its own
passphrase (Argon2id, XChaCha20-Poly1305 in authenticated chunks), and the
vault inside stays locked with the vault's passphrase.

## What Conduit does not protect against

- **Anything you allow.** A rule that allows an action lets an agent run it
  without asking. Keep destructive actions on approval for anything that
  must not go wrong.
- **External modules and MCP servers.** A module or MCP server you run
  outside the sandbox runs as you, like any program you install. Its calls
  still pass the policy engine and the audit log, but what it does on your
  computer is up to it. Install only what you trust.
- **What a service does with an approved call.** Conduit checks the call
  and the preview; the service on the other end carries it out.
- **Code running as the daemon's user while the vault is unlocked.** It can
  read secrets from memory. The emergency stop locks the vault.
- **A lost passphrase.** Without the vault or backup passphrase, the data
  can't be decrypted. That is the point; keep it safe.
- **A lost or stolen phone.** It can reach your daemon until you remove it
  in Settings, Remote access. Use a screen lock; approvals on the phone ask
  for a fingerprint, face or PIN first.

## Supported versions

Only the latest release gets fixes.
