-- Outbound webhooks: events POSTed to a URL, signed with HMAC-SHA256.
CREATE TABLE webhooks (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  url         TEXT NOT NULL,
  events      TEXT NOT NULL DEFAULT '[]', -- JSON array of type prefixes; empty = all
  secret      TEXT NOT NULL,
  enabled     INTEGER NOT NULL DEFAULT 1,
  failures    INTEGER NOT NULL DEFAULT 0, -- consecutive failed deliveries
  created_at  TEXT NOT NULL
);

CREATE TABLE webhook_deliveries (
  id          TEXT PRIMARY KEY,
  webhook_id  TEXT NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
  event       TEXT NOT NULL,
  at          TEXT NOT NULL,
  status      INTEGER NOT NULL DEFAULT 0, -- last HTTP status, 0 = no answer
  attempts    INTEGER NOT NULL DEFAULT 0,
  ok          INTEGER NOT NULL DEFAULT 0,
  error       TEXT NOT NULL DEFAULT '',
  duration_ms INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX webhook_deliveries_by_hook ON webhook_deliveries (webhook_id, at);
