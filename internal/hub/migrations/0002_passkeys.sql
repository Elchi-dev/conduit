-- Passkeys (WebAuthn credentials) for hub accounts. The credential, as
-- stored by github.com/go-webauthn/webauthn, is kept as JSON text.
CREATE TABLE passkeys (
  id            TEXT PRIMARY KEY,
  account_id    TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  credential_id TEXT NOT NULL UNIQUE, -- base64url of the raw credential id
  name          TEXT NOT NULL,
  credential    TEXT NOT NULL,
  created_at    TEXT NOT NULL,
  last_used_at  TEXT
);
CREATE INDEX passkeys_by_account ON passkeys (account_id);
