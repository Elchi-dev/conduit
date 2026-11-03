-- Operator console (internal/hub/admin.go): hub admins can switch accounts
-- off, and see when each account last signed in.
ALTER TABLE accounts ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE accounts ADD COLUMN last_sign_in_at TEXT NOT NULL DEFAULT ''
