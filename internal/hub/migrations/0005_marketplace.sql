-- The marketplace (internal/hub/marketplace.go, docs/protocol/marketplace.md):
-- listings, install counts, ratings and reviews, reports and moderation.
-- Portable between SQLite and PostgreSQL like 0001.

-- Listing metadata, set by the author apart from signed versions. tags and
-- screenshots are JSON text; icon is a registry_media id.
ALTER TABLE registry_packages ADD COLUMN readme TEXT NOT NULL DEFAULT '';
ALTER TABLE registry_packages ADD COLUMN tags TEXT NOT NULL DEFAULT '[]';
ALTER TABLE registry_packages ADD COLUMN source_url TEXT NOT NULL DEFAULT '';
ALTER TABLE registry_packages ADD COLUMN license TEXT NOT NULL DEFAULT '';
ALTER TABLE registry_packages ADD COLUMN icon TEXT NOT NULL DEFAULT '';
ALTER TABLE registry_packages ADD COLUMN screenshots TEXT NOT NULL DEFAULT '[]';
-- Active installs (daemons that have it now); downloads counts installs ever.
ALTER TABLE registry_packages ADD COLUMN installs BIGINT NOT NULL DEFAULT 0;
-- Kept in step with registry_reviews for sorting.
ALTER TABLE registry_packages ADD COLUMN rating_count BIGINT NOT NULL DEFAULT 0;
ALTER TABLE registry_packages ADD COLUMN rating_sum BIGINT NOT NULL DEFAULT 0;
-- Delisted by an operator: hidden from search; daemons warn whoever has it.
ALTER TABLE registry_packages ADD COLUMN delisted INTEGER NOT NULL DEFAULT 0;
ALTER TABLE registry_packages ADD COLUMN delist_reason TEXT NOT NULL DEFAULT '';
ALTER TABLE registry_packages ADD COLUMN delist_note TEXT NOT NULL DEFAULT '';
ALTER TABLE registry_packages ADD COLUMN delisted_at TEXT NOT NULL DEFAULT '';

-- Who yanked a version and why: by 'author' (reason empty) or 'operator'.
ALTER TABLE registry_versions ADD COLUMN yanked_by TEXT NOT NULL DEFAULT '';
ALTER TABLE registry_versions ADD COLUMN yank_reason TEXT NOT NULL DEFAULT '';
ALTER TABLE registry_versions ADD COLUMN yank_note TEXT NOT NULL DEFAULT '';
ALTER TABLE registry_versions ADD COLUMN yanked_at TEXT NOT NULL DEFAULT '';

-- Verified by an operator; banned authors keep their handle and key as a
-- tombstone so nobody can take them over.
ALTER TABLE registry_authors ADD COLUMN verified INTEGER NOT NULL DEFAULT 0;
ALTER TABLE registry_authors ADD COLUMN banned INTEGER NOT NULL DEFAULT 0;
ALTER TABLE registry_authors ADD COLUMN ban_reason TEXT NOT NULL DEFAULT '';
ALTER TABLE registry_authors ADD COLUMN banned_at TEXT NOT NULL DEFAULT '';

CREATE TABLE registry_package_categories (
  name     TEXT NOT NULL,
  category TEXT NOT NULL,
  PRIMARY KEY (name, category)
);
CREATE INDEX registry_package_categories_by_category ON registry_package_categories (category);

-- Icons and screenshots: PNG or WebP only, base64, content-addressed.
CREATE TABLE registry_media (
  id           TEXT PRIMARY KEY,
  name         TEXT NOT NULL,
  content_type TEXT NOT NULL,
  data         TEXT NOT NULL,
  created_at   TEXT NOT NULL
);
CREATE INDEX registry_media_by_name ON registry_media (name);

-- Anonymous install pings. daemon is an opaque per-daemon-per-package id;
-- one ping of each kind counts per daemon per day.
CREATE TABLE registry_install_pings (
  name   TEXT NOT NULL,
  daemon TEXT NOT NULL,
  day    TEXT NOT NULL,
  event  TEXT NOT NULL,
  PRIMARY KEY (name, daemon, day, event)
);
CREATE TABLE registry_active_installs (
  name       TEXT NOT NULL,
  daemon     TEXT NOT NULL,
  version    TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (name, daemon)
);

-- One rating and review per account per package.
CREATE TABLE registry_reviews (
  id         TEXT NOT NULL UNIQUE,
  name       TEXT NOT NULL,
  account_id TEXT NOT NULL,
  rating     INTEGER NOT NULL,
  body       TEXT NOT NULL DEFAULT '',
  version    TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  reply      TEXT NOT NULL DEFAULT '',
  reply_at   TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (name, account_id)
);

-- Reports about a package or one of its versions.
CREATE TABLE registry_reports (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  version     TEXT NOT NULL DEFAULT '',
  account_id  TEXT NOT NULL,
  reason      TEXT NOT NULL,
  details     TEXT NOT NULL DEFAULT '',
  status      TEXT NOT NULL DEFAULT 'open',
  action      TEXT NOT NULL DEFAULT '',
  note        TEXT NOT NULL DEFAULT '',
  resolved_by TEXT NOT NULL DEFAULT '',
  created_at  TEXT NOT NULL,
  resolved_at TEXT NOT NULL DEFAULT ''
);
CREATE INDEX registry_reports_by_status ON registry_reports (status, created_at);
CREATE UNIQUE INDEX registry_reports_one_open ON registry_reports (name, account_id) WHERE status = 'open'
