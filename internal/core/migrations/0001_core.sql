-- Module instances: one row per configured instance of a module.
CREATE TABLE instances (
  id          TEXT PRIMARY KEY,
  module      TEXT NOT NULL,
  name        TEXT NOT NULL,
  config      TEXT NOT NULL DEFAULT '{}',
  enabled     INTEGER NOT NULL DEFAULT 1,
  created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

-- Policy rules, evaluated in ascending position; first match wins.
CREATE TABLE policy_rules (
  id          TEXT PRIMARY KEY,
  position    INTEGER NOT NULL,
  subject     TEXT NOT NULL DEFAULT '*',
  module      TEXT NOT NULL DEFAULT '*',
  instance    TEXT NOT NULL DEFAULT '*',
  action      TEXT NOT NULL DEFAULT '*',
  risk        TEXT NOT NULL DEFAULT '*',
  effect      TEXT NOT NULL CHECK (effect IN ('allow','ask','deny')),
  expires_at  TEXT,
  note        TEXT NOT NULL DEFAULT ''
);

-- Append-only, hash-chained audit log.
CREATE TABLE audit_log (
  seq         INTEGER PRIMARY KEY AUTOINCREMENT,
  at          TEXT NOT NULL,
  actor       TEXT NOT NULL,
  actor_kind  TEXT NOT NULL,
  module      TEXT NOT NULL,
  instance    TEXT NOT NULL,
  action      TEXT NOT NULL,
  risk        TEXT NOT NULL,
  decision    TEXT NOT NULL,
  status      TEXT NOT NULL,
  dry_run     INTEGER NOT NULL DEFAULT 0,
  input       TEXT NOT NULL DEFAULT 'null',
  output      TEXT NOT NULL DEFAULT 'null',
  error       TEXT NOT NULL DEFAULT '',
  undo        TEXT,
  undone_by   INTEGER,
  undoes      INTEGER,
  prev_hash   TEXT NOT NULL,
  hash        TEXT NOT NULL UNIQUE
);
CREATE INDEX audit_log_at ON audit_log(at);
CREATE INDEX audit_log_module ON audit_log(module, instance);

-- Approvals waiting for, or decided by, a human.
CREATE TABLE approvals (
  id          TEXT PRIMARY KEY,
  created_at  TEXT NOT NULL,
  actor       TEXT NOT NULL,
  actor_kind  TEXT NOT NULL,
  module      TEXT NOT NULL,
  instance    TEXT NOT NULL,
  action      TEXT NOT NULL,
  risk        TEXT NOT NULL,
  input       TEXT NOT NULL DEFAULT 'null',
  plan        TEXT,
  status      TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','denied','expired')),
  decided_by  TEXT,
  decided_at  TEXT,
  expires_at  TEXT NOT NULL
);
CREATE INDEX approvals_status ON approvals(status);

-- Small key/value settings (kill switch, active policy preset, ...).
CREATE TABLE settings (
  key         TEXT PRIMARY KEY,
  value       TEXT NOT NULL
)
