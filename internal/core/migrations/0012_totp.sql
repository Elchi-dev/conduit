-- Two-factor sign-in with authenticator apps (internal/totp). The secret is
-- encrypted under a key kept in settings (auth.totp_key). A row with
-- enabled = 0 is an enrollment that hasn't been confirmed with a code yet.
CREATE TABLE user_totp (
  user_id    TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  secret     TEXT NOT NULL,
  enabled    INTEGER NOT NULL DEFAULT 0,
  last_step  INTEGER NOT NULL DEFAULT 0, -- the last time step used; older ones are refused
  created_at TEXT NOT NULL,
  enabled_at TEXT
);

-- One-time recovery codes, hashed.
CREATE TABLE user_recovery_codes (
  user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,
  used_at   TEXT,
  PRIMARY KEY (user_id, code_hash)
);
