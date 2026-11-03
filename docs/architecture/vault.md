# Vault design

Code: `internal/vault` (storage and crypto), `modules/vault` (the module).

## Keys

```
passphrase ──Argon2id(salt, t=3, m=64 MiB, p=2)──▶ key-encryption key
                                                       │ XChaCha20-Poly1305
                                                       ▼
                                   wrapped data key (stored in vault_meta)
data key (256-bit, random) ──XChaCha20-Poly1305, AD = secret name──▶ each secret
```

- The data key never touches disk in clear. In memory it exists only while
  the vault is unlocked and is zeroed on lock.
- Each secret has its own random 192-bit nonce. Binding the secret's name as
  associated data means a ciphertext copied to another row fails to decrypt
  instead of returning the wrong secret.
- Changing the passphrase only re-wraps the data key (planned; the format
  supports it without re-encrypting secrets).
- "Remember on this computer" stores the data key in the OS keychain under the
  service `dev.elchi.conduit.vault`, with an account derived from the data
  directory, so several daemons on one machine don't collide. On start the
  remembered key is checked against a stored secret before it is trusted.

## Who can read a secret

1. **People** use the `reveal` action, which is destructive and therefore
   needs approval for anyone but a signed-in person.
2. **Modules** call `Host.Secret(ref)`. The engine only resolves references
   that appear in that module instance's own settings, so a module can't
   enumerate or read other secrets.
3. **Agents** never see values unless a person approves `reveal` or `totp`
   for them, or a rule explicitly allows it.

Sensitive actions are redacted everywhere Conduit persists or broadcasts:
audit entries keep field names and the `name` of the secret, and replace
every other value with `"[redacted]"`.

## Threat notes

- Someone with the database file but not the passphrase (or keychain) sees
  secret names, kinds and timestamps, and cannot decrypt values.
- Someone with code execution as the daemon's user while the vault is unlocked
  can read secrets from memory; the emergency stop locks the vault.
- The audit log's hash chain makes later edits to records of secret access
  detectable.

## Restricted folders (teams)

The owner can restrict folders of the vault (People, Restricted vault
folders; `PUT /api/v1/vault/folders`): secrets whose names start with
`finance/`, say, can then only be revealed, changed, deleted, imported into
or used in settings (module instances, AI providers, MCP servers, single
sign-on, the backup passphrase) by the roles and people the folder lists.
Agents and API keys get exactly what their owner gets. Automations only
when the folder allows them, and only if the person who last saved the
automation may use the folder too (so allowing automations doesn't let
everyone who can write one read the folder). The owner always keeps
access, and only the owner changes restrictions, since they bind admins
too. The most specific folder wins. Names stay visible to everyone who can
see the vault.

A few things go through every secret at once, so they need access to every
restricted folder: checking text or a folder for leaked values (a match
would confirm a guess), and syncing the vault to other daemons. While any
folder is restricted, only the owner can create, join or add the vault to
a sync group, or see its join code. Imports check each name they would
write; a `.env` key can't choose a folder (`FINANCE/BANK` without a prefix
becomes `imported/finance-bank`). Settings are checked after decoding, so
escaped forms such as `secret:\/\/finance\/bank` are caught.

Enforcement is an engine guard (`core.Engine.Guard`) that runs before the
policy for every call, so it holds for the app, the API, MCP, automations
and undo alike; refusals are audited as denied. Module instances that
already referenced a secret before its folder was restricted keep working.
