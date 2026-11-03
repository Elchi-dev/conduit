-- AI model providers. API keys are vault references, never stored here.
CREATE TABLE ai_providers (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  kind        TEXT NOT NULL CHECK (kind IN ('anthropic','openai')),
  base_url    TEXT NOT NULL,
  model       TEXT NOT NULL,
  api_key     TEXT NOT NULL DEFAULT '',
  headers     TEXT NOT NULL DEFAULT '{}',
  is_default  INTEGER NOT NULL DEFAULT 0,
  created_at  TEXT NOT NULL
);

-- Conversations with the built-in assistant.
CREATE TABLE ai_conversations (
  id          TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL,
  title       TEXT NOT NULL,
  provider    TEXT NOT NULL,
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL
);
CREATE INDEX ai_conversations_user ON ai_conversations(user_id, updated_at);

CREATE TABLE ai_messages (
  conversation TEXT NOT NULL REFERENCES ai_conversations(id) ON DELETE CASCADE,
  seq          INTEGER NOT NULL,
  body         TEXT NOT NULL,
  created_at   TEXT NOT NULL,
  PRIMARY KEY (conversation, seq)
)
