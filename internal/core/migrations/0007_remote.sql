-- Remote access through a hub (internal/remote).
-- The link to a hub: at most one row.
CREATE TABLE remote_link (
  id         INTEGER PRIMARY KEY CHECK (id = 1),
  hub        TEXT NOT NULL,
  device_id  TEXT NOT NULL,
  token      TEXT NOT NULL,
  account    TEXT NOT NULL DEFAULT '',
  linked_at  TEXT NOT NULL
);

-- Clients (phones, browsers elsewhere) allowed to open relay sessions,
-- recognised by their X25519 public key.
CREATE TABLE relay_clients (
  id           TEXT PRIMARY KEY,
  name         TEXT NOT NULL,
  public_key   TEXT NOT NULL UNIQUE,
  created_at   TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  revoked      INTEGER NOT NULL DEFAULT 0
);
