-- Single sign-on identities linked to local accounts: the provider's stable
-- subject, never the email address, decides which account signs in.
CREATE TABLE oidc_links (
  issuer     TEXT NOT NULL,
  subject    TEXT NOT NULL,
  user_id    TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (issuer, subject)
);
CREATE INDEX oidc_links_by_user ON oidc_links (user_id);
