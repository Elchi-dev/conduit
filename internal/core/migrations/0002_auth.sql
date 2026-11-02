-- Local accounts. The first user created is the owner.
CREATE TABLE users (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL,
  email         TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role          TEXT NOT NULL CHECK (role IN ('owner','admin','member','viewer')),
  created_at    TEXT NOT NULL,
  disabled      INTEGER NOT NULL DEFAULT 0
);

-- Sessions for people signed in to a client. Only a hash of the token is stored.
CREATE TABLE sessions (
  id            TEXT PRIMARY KEY,
  token_hash    TEXT NOT NULL UNIQUE,
  user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device        TEXT NOT NULL DEFAULT '',
  created_at    TEXT NOT NULL,
  last_seen_at  TEXT NOT NULL,
  expires_at    TEXT NOT NULL,
  revoked_at    TEXT
);
CREATE INDEX sessions_user ON sessions(user_id);

-- API keys. Only a hash of the secret part is stored; the full key is shown once.
CREATE TABLE api_keys (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL,
  kind          TEXT NOT NULL CHECK (kind IN ('live','test','agent')),
  prefix        TEXT NOT NULL,
  secret_hash   TEXT NOT NULL UNIQUE,
  owner_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  scopes        TEXT NOT NULL DEFAULT '[]',
  ip_allow      TEXT NOT NULL DEFAULT '[]',
  rate_per_min  INTEGER NOT NULL DEFAULT 120,
  created_at    TEXT NOT NULL,
  expires_at    TEXT,
  last_used_at  TEXT,
  revoked_at    TEXT,
  revoke_reason TEXT NOT NULL DEFAULT '',
  rotated_to    TEXT,
  grace_until   TEXT
);
CREATE INDEX api_keys_owner ON api_keys(owner_id);

-- Per-request usage log for API keys (rolling; pruned after 30 days).
CREATE TABLE api_key_usage (
  key_id        TEXT NOT NULL,
  at            TEXT NOT NULL,
  method        TEXT NOT NULL,
  path          TEXT NOT NULL,
  status        INTEGER NOT NULL,
  ip            TEXT NOT NULL DEFAULT ''
);
CREATE INDEX api_key_usage_key ON api_key_usage(key_id, at)
