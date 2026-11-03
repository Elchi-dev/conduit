-- Sync (internal/syncer): the last document every side agreed on, per
-- collection. The group key and settings live in the settings table.
CREATE TABLE sync_state (
  collection TEXT PRIMARY KEY,
  doc        TEXT NOT NULL
);
