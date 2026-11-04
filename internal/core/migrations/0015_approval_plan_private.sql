-- Whether an approval's plan is shown only to people who can decide
-- approvals (sensitive actions, or a caller denied some of the module's
-- reads). Everyone else sees it redacted.
ALTER TABLE approvals ADD COLUMN plan_private INTEGER NOT NULL DEFAULT 0;
