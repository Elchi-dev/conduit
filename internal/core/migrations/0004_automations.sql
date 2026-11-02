-- Automations: a trigger plus a chain of action steps, stored as JSON.
CREATE TABLE automations (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  enabled     INTEGER NOT NULL DEFAULT 0,
  spec        TEXT NOT NULL,
  hook_token  TEXT UNIQUE,
  created_by  TEXT NOT NULL,
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL
);

CREATE TABLE automation_runs (
  id          TEXT PRIMARY KEY,
  automation  TEXT NOT NULL,
  started_at  TEXT NOT NULL,
  finished_at TEXT,
  trigger     TEXT NOT NULL,
  status      TEXT NOT NULL,
  steps       TEXT NOT NULL DEFAULT '[]',
  error       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX automation_runs_by ON automation_runs(automation, started_at)
