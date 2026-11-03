# Vault

Encrypted passwords, tokens, notes, SSH keys and two-factor (TOTP) secrets.
Other modules never store credentials; their settings hold references like
`secret://mail/work`, resolved by the vault at the moment they are needed.

## Setting it up

Open **Vault** and choose a passphrase (12 characters or more). Conduit
cannot recover it. Tick "Unlock automatically on this computer" to keep the
key in the system keychain (macOS Keychain, Windows Credential Manager or the
Linux Secret Service), so the vault opens when Conduit starts.

While locked, secret names are visible but no module can use a secret, and
every module that needs one reports itself as degraded.

## Actions

| Action | Risk | What it does |
| --- | --- | --- |
| `list` | read | Names, kinds, descriptions, last use. Never values. |
| `generate` | read | A random password (16–128 characters), not stored |
| `scan_text` | read | Finds vault secret values in pasted text, by secret name and line |
| `rotate` | destructive | Gets a fresh value from the issuing service and stores it, keeping the secret's details; the old value stops working. Providers: `cloudflare` (the token needs permission to roll itself). More providers plug in through `vault.RegisterRotator`. |
| `scan_path` | read | Same for a file or folder on the machine running Conduit; skips `.git`, `node_modules`, build output, binaries and files over 2 MiB |
| `set` | write | Create or replace a secret; an empty value generates a password |
| `import_env` | write | Stores each `KEY=value` line of a `.env` file as `<prefix>/<key>` |
| `reveal` | destructive | Returns a secret's value |
| `totp` | destructive | The current 6-digit code for a TOTP secret (base32 or `otpauth://` URI) |
| `delete` | destructive | Removes a secret |

`reveal`, `totp`, `set`, `generate`, `import_env` and `scan_text` are
**sensitive**: Conduit never writes their values to the audit log, approvals
or events. The log still records which secret was touched, by whom and when.

With the default agent rules, agents can list secrets and check for leaks,
must ask to save one, and must ask (with the request showing exactly which
secret) to reveal one or read a one-time code.

## Leak watch

`scan_text` and `scan_path` compare text against every secret value of 8
characters or more and report the secret's name and the line, never the
value. Point `scan_path` at a code repository before you push, or run it on a
schedule from Automations.

Automatic rotation (replacing a leaked credential with the provider) is
planned for providers that support it; the module reports leaks today.

## Unlock, lock and the emergency stop

| Endpoint | Who |
| --- | --- |
| `POST /api/v1/vault/setup` | owner or admin, signed in |
| `POST /api/v1/vault/unlock` | owner or admin, signed in |
| `POST /api/v1/vault/lock` | anyone authenticated (locking only reduces access) |

The emergency stop locks the vault.

## How secrets are protected

See [the vault design](../architecture/vault.md).

## Leak watch and rotation

Signature feature 7. `scan_text` and `scan_path` find vault values in logs,
pastes and repositories. When one leaks, `rotate` replaces it at the source
where the service allows it, so the leaked copy is dead. Automations can run
`scan_path` on a schedule and notify you of findings; rotation stays a
destructive action, so agents ask first.
