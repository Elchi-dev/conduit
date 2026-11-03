-- Two-factor sign-in with authenticator apps (internal/totp). Secrets are
-- encrypted under hub_settings.totp_key. enabled = 0 is an unconfirmed setup.
CREATE TABLE hub_settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE account_totp (
  account_id TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
  secret     TEXT NOT NULL,
  enabled    INTEGER NOT NULL DEFAULT 0,
  last_step  BIGINT NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE TABLE account_recovery_codes (
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  code_hash  TEXT NOT NULL,
  used_at    TEXT,
  PRIMARY KEY (account_id, code_hash)
);
