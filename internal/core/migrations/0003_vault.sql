-- Vault parameters: one row. The data key is stored only wrapped (encrypted)
-- by a key derived from the passphrase.
CREATE TABLE vault_meta (
  id           INTEGER PRIMARY KEY CHECK (id = 1),
  kdf_salt     BLOB NOT NULL,
  kdf_time     INTEGER NOT NULL,
  kdf_memory   INTEGER NOT NULL,
  kdf_threads  INTEGER NOT NULL,
  wrapped_key  BLOB NOT NULL,
  created_at   TEXT NOT NULL
);

-- Secrets, each sealed with XChaCha20-Poly1305 under the data key. The name
-- is bound as associated data, so a ciphertext cannot be moved to another name.
CREATE TABLE vault_secrets (
  name         TEXT PRIMARY KEY,
  kind         TEXT NOT NULL,
  ciphertext   BLOB NOT NULL,
  description  TEXT NOT NULL DEFAULT '',
  tags         TEXT NOT NULL DEFAULT '[]',
  created_at   TEXT NOT NULL,
  updated_at   TEXT NOT NULL,
  last_used_at TEXT
)
