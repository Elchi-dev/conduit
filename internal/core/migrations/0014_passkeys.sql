-- Passkeys (WebAuthn) for signing in to people accounts. The RP ID is the
-- host name the daemon is opened under (localhost, or a name allowed by
-- CONDUIT_ALLOWED_HOSTS), so a passkey only works at the address it was
-- added at. credential_id is the base64url credential ID; public_key the
-- COSE key. credential is the library's full record as JSON (flags, AAGUID,
-- attestation), kept so later checks (such as the backup-eligible flag)
-- have what they need; sign_count and transports are the source of truth.
CREATE TABLE user_passkeys (
  id            TEXT PRIMARY KEY,
  user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  rp_id         TEXT NOT NULL,
  credential_id TEXT NOT NULL UNIQUE,
  public_key    BLOB NOT NULL,
  sign_count    INTEGER NOT NULL DEFAULT 0,
  transports    TEXT NOT NULL DEFAULT '',
  credential    TEXT NOT NULL,
  name          TEXT NOT NULL,
  created_at    TEXT NOT NULL,
  last_used_at  TEXT
);
CREATE INDEX user_passkeys_user ON user_passkeys(user_id);
