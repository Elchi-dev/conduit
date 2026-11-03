# Backups

A backup is one encrypted file (`.cdb`) with everything a daemon has:
settings, module instances, agent rules, keys, automations, the audit log,
sync state, notes and sandboxed modules, and the vault. The vault inside
stays locked with its own passphrase; the backup adds a second one.

Everything else is readable to whoever has the file and its passphrase,
including the key that encrypts two-factor secrets and the remote-access
relay key, so treat the backup passphrase like the owner's password.

## Take a backup

- **In the app:** Settings, Backups, choose a passphrase (at least 12
  characters) and **Download a backup**. Only signed-in people can.
- **Every day:** in the same place, turn on **Write a backup every day**,
  pick a folder (another disk, a NAS mount or a synced folder), and store
  the passphrase in the vault first (Vault module, Save a secret, for
  example `backup/passphrase`), then enter `secret://backup/passphrase`.
  The newest backups are kept (7 by default). Scheduled backups need the
  vault unlocked.
- **From a shell**, also while the daemon runs:

  ```sh
  CONDUIT_BACKUP_PASSPHRASE='…' conduitd backup -out conduit-backup.cdb
  ```

## Restore

Restore into a new, empty folder, then start the daemon on it:

```sh
CONDUIT_BACKUP_PASSPHRASE='…' conduitd restore -data /path/to/new-folder -in conduit-backup.cdb
conduitd -data /path/to/new-folder
```

Then unlock the vault with its passphrase. Sessions from before the backup
still work until they expire; sign out everywhere if the backup was old or
you're moving to a new machine.

## What's not in a backup

- The setup token (one-time) and the live database's journal files (a
  consistent snapshot is taken instead).
- Earlier scheduled backups.
- Secrets kept only in the OS keychain (the "remember on this computer"
  vault unlock): unlock with the vault passphrase after restoring.

## How it's protected

The passphrase becomes a key with Argon2id (64 MiB, 3 passes). The archive
is encrypted with XChaCha20-Poly1305 in 64 KiB chunks; each chunk's nonce
holds a random prefix, its number and a final-chunk flag, and the file's
header is bound to every chunk, so a changed, reordered, cut-off or
shortened file fails to restore, and nothing is written until it has all
decrypted. Code: `internal/backup`.
