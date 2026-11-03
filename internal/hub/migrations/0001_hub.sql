-- Portable between SQLite and PostgreSQL: TEXT, BIGINT and INTEGER only;
-- booleans are 0/1 integers; times are RFC 3339 strings.
CREATE TABLE accounts (
  id            TEXT PRIMARY KEY,
  email         TEXT NOT NULL UNIQUE,
  name          TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  verified      INTEGER NOT NULL DEFAULT 0,
  is_admin      INTEGER NOT NULL DEFAULT 0,
  created_at    TEXT NOT NULL
);

CREATE TABLE hub_sessions (
  token_hash  TEXT PRIMARY KEY,
  account_id  TEXT NOT NULL,
  device      TEXT NOT NULL DEFAULT '',
  created_at  TEXT NOT NULL,
  expires_at  TEXT NOT NULL,
  revoked     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX hub_sessions_account ON hub_sessions(account_id);

-- One-time tokens sent by email: verify, reset, invite.
CREATE TABLE email_tokens (
  token_hash  TEXT PRIMARY KEY,
  account_id  TEXT NOT NULL DEFAULT '',
  kind        TEXT NOT NULL,
  data        TEXT NOT NULL DEFAULT '{}',
  expires_at  TEXT NOT NULL,
  used        INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE orgs (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  created_at  TEXT NOT NULL
);

CREATE TABLE org_members (
  org_id      TEXT NOT NULL,
  account_id  TEXT NOT NULL,
  role        TEXT NOT NULL,
  created_at  TEXT NOT NULL,
  PRIMARY KEY (org_id, account_id)
);

-- Daemons and clients paired to an account. The token authenticates the
-- device to the hub; the public key is for end-to-end encryption and is
-- published for convenience only (clients pin keys from pairing QR codes).
CREATE TABLE devices (
  id            TEXT PRIMARY KEY,
  account_id    TEXT NOT NULL,
  name          TEXT NOT NULL,
  kind          TEXT NOT NULL,
  public_key    TEXT NOT NULL,
  token_hash    TEXT NOT NULL UNIQUE,
  created_at    TEXT NOT NULL,
  last_seen_at  TEXT NOT NULL,
  revoked       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX devices_account ON devices(account_id);

CREATE TABLE pairing_codes (
  code_hash   TEXT PRIMARY KEY,
  account_id  TEXT NOT NULL,
  expires_at  TEXT NOT NULL,
  used        INTEGER NOT NULL DEFAULT 0
);

-- Opaque, client-encrypted blobs with optimistic versioning.
CREATE TABLE sync_blobs (
  account_id  TEXT NOT NULL,
  blob_key    TEXT NOT NULL,
  version     BIGINT NOT NULL,
  data        TEXT NOT NULL,
  updated_at  TEXT NOT NULL,
  PRIMARY KEY (account_id, blob_key)
);

-- Hub API keys for developers (publishing modules, scripting the hub).
CREATE TABLE hub_keys (
  id          TEXT PRIMARY KEY,
  account_id  TEXT NOT NULL,
  name        TEXT NOT NULL,
  prefix      TEXT NOT NULL,
  secret_hash TEXT NOT NULL UNIQUE,
  scopes      TEXT NOT NULL,
  created_at  TEXT NOT NULL,
  revoked     INTEGER NOT NULL DEFAULT 0
);

-- Module registry. Authors sign versions with an ed25519 key registered here.
CREATE TABLE registry_authors (
  account_id  TEXT PRIMARY KEY,
  handle      TEXT NOT NULL UNIQUE,
  public_key  TEXT NOT NULL,
  created_at  TEXT NOT NULL
);

CREATE TABLE registry_packages (
  name        TEXT PRIMARY KEY,
  owner       TEXT NOT NULL,
  description TEXT NOT NULL,
  homepage    TEXT NOT NULL DEFAULT '',
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL,
  downloads   BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE registry_versions (
  name        TEXT NOT NULL,
  version     TEXT NOT NULL,
  payload     TEXT NOT NULL, -- base64 of the exact bytes the author signed
  artifacts   TEXT NOT NULL,
  signature   TEXT NOT NULL,
  created_at  TEXT NOT NULL,
  yanked      INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (name, version)
);

-- Signed release manifests for the update feed.
CREATE TABLE releases (
  component   TEXT NOT NULL,
  channel     TEXT NOT NULL,
  platform    TEXT NOT NULL,
  version     TEXT NOT NULL,
  payload     TEXT NOT NULL, -- base64 of the exact bytes the release key signed
  sha256      TEXT NOT NULL,
  signature   TEXT NOT NULL,
  notes       TEXT NOT NULL DEFAULT '',
  created_at  TEXT NOT NULL,
  PRIMARY KEY (component, channel, platform, version)
)
