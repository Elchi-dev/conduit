-- Networks (internal/wgnet): userspace WireGuard tunnels that module
-- instances can be attached to. config is the JSON wgnet.Config; key
-- material lives in the vault and is only referenced (secret://).
CREATE TABLE networks (
  id         TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  config     TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

-- The network an instance's outbound connections go through ('' = none).
ALTER TABLE instances ADD COLUMN network TEXT NOT NULL DEFAULT '';
