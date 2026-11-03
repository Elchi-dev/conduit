-- Outside MCP servers mounted as modules. Credentials are vault references.
CREATE TABLE mcp_servers (
  id    TEXT PRIMARY KEY,
  name  TEXT NOT NULL,
  spec  TEXT NOT NULL
)
