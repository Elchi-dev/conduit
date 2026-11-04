# SOPS files

The [SOPS](https://getsops.io)-encrypted files in a folder on this machine,
such as a GitOps repository, and their metadata, without decrypting
anything: key names and whether each value is encrypted, the recipients
each file is encrypted to, when SOPS last changed it, its settings, and the
creation rules of `.sops.yaml`. The module holds no decryption key and has
no way to use one, never returns a value (encrypted, or left in the clear by
`unencrypted_suffix` and the like), never returns the encrypted data keys,
and never writes. Every action is read-only.

**Setup.** Enter the absolute path of the `folder`. Sub-folders are included
up to 8 levels; `.git`, `node_modules`, `vendor`, `.terraform` and `.venv`
are skipped, symlinks are never followed, and files over 1 MiB are ignored.
A file counts as SOPS-encrypted when it has SOPS metadata: a `sops` section
in YAML or JSON (including SOPS's binary format), `sops_…` lines in a
dotenv file, or a `[sops]` section in an INI file.

| Action | Risk | Notes |
| --- | --- | --- |
| `files` | read | Each SOPS file: path, format, SOPS version, last change (`lastmodified`), number of keys and of encrypted keys, recipients by type, size and file time; files without a MAC are flagged. `olderThanDays` keeps only files SOPS last changed longer ago, to find secrets that haven't been rotated. |
| `file` | read | One file (path relative to the folder): every key path (`db.password`, `replicas[0].host`, `doc2:…` in multi-document YAML) and whether its value is encrypted, its recipients with key groups and creation times, `lastmodified`, whether it has a MAC, and settings such as `encrypted_regex` and `shamir_threshold`. |
| `recipients` | read | Every recipient (age key, PGP fingerprint, AWS KMS ARN, GCP KMS resource, Azure Key Vault key, Vault transit key) with the files encrypted to it, and files with none: what to re-encrypt when a key is retired or a person leaves. |
| `rules` | read | The creation rules of the folder's `.sops.yaml`: path pattern, recipients, key groups and which keys get encrypted. |

**Security.** The folder is opened as a Go `os.Root`, so a path that leaves
it (`..`, an absolute path, a symlink pointing out) is refused. Files are
parsed only far enough to find their keys and SOPS metadata, with a parser
for the block YAML SOPS writes (no anchors expanded, nesting capped); a
value is looked at only to see whether it starts with `ENC[`. Parsing is
linear in the file's size and bounded: a value may span at most 10,000
lines, a dotenv or INI file's flattened `sops_…` keys at most 64 levels,
list indexes below 64 and 10,000 nodes in all (a file over them is
ignored), each file gets 2 seconds of parsing, and a scan reads at most
64 MiB in 20 seconds (then reports `truncated`); a cancelled call stops
parsing. Files are opened non-blocking and checked to be regular files once
open, so one swapped for a FIFO or device after it was listed is never
waited on.
