package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

func TestCheckStatement(t *testing.T) {
	ok := []string{
		"SELECT 1",
		"select * from users where name = 'a;b' ;",
		"WITH x AS (SELECT 1) SELECT * FROM x",
		"-- note; with a semicolon\nSELECT 2",
		"SELECT $$a;b$$",
		"SELECT \"weird;name\" FROM t",
		"EXPLAIN SELECT 1",
		"SHOW TABLES",
	}
	for _, q := range ok {
		if err := CheckStatement(q); err != nil {
			t.Errorf("%q refused: %v", q, err)
		}
	}
	bad := []string{
		"",
		"DELETE FROM users",
		"SELECT 1; DROP TABLE users",
		"select 1; select 2",
		"UPDATE t SET a = 1",
		"/* comment */ INSERT INTO t VALUES (1)",
		"SELECT * INTO OUTFILE '/tmp/x' FROM t",
		"SELECT pg_read_file('/etc/passwd')",
		"SELECT 'unterminated",
		"SELECT $$unterminated",
		"COPY t TO PROGRAM 'id'",
		"SELECT pg_sleep(100)",
	}
	for _, q := range bad {
		if err := CheckStatement(q); err == nil {
			t.Errorf("%q accepted", q)
		}
	}
}

func TestDSN(t *testing.T) {
	pg, err := DSN(Config{Kind: "postgres", Host: "db.internal", User: "ro", Database: "app"}, "p@ss/w:rd")
	if err != nil || !strings.HasPrefix(pg, "postgres://ro:p%40ss%2Fw%3Ard@db.internal:5432/app?") || !strings.Contains(pg, "sslmode=verify-full") {
		t.Fatalf("postgres: %s %v", pg, err)
	}
	local, _ := DSN(Config{Kind: "postgres", Host: "localhost", User: "ro", Database: "app"}, "x")
	if !strings.Contains(local, "sslmode=disable") {
		t.Fatalf("localhost: %s", local)
	}
	my, err := DSN(Config{Kind: "mysql", Host: "db", Port: 3307, User: "ro", Database: "app", TLS: "require"}, "pw")
	if err != nil || !strings.Contains(my, "@tcp(db:3307)/app") || !strings.Contains(my, "tls=skip-verify") || strings.Contains(my, "multiStatements=true") {
		t.Fatalf("mysql: %s %v", my, err)
	}
	if _, err := DSN(Config{Kind: "oracle"}, ""); err == nil {
		t.Fatal("unknown kind accepted")
	}
}

// The query path against SQLite, standing in for the real databases: the
// statement check, the read-only transaction and the row cap.
func TestQueryReadOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.db")
	setup, _ := sql.Open("sqlite", path)
	if _, err := setup.Exec(`CREATE TABLE users (id INTEGER, name TEXT); WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < 1500) INSERT INTO users SELECT i, 'user ' || i FROM n`); err != nil {
		t.Fatal(err)
	}
	setup.Close()

	m := New()
	m.dialects = map[string]dialect{"postgres": {
		driver:   "sqlite",
		readOnly: `PRAGMA query_only = ON`,
		tables:   `SELECT 'main', name, 0 FROM sqlite_master WHERE type = 'table'`,
		stats:    `SELECT 4096, 1, 0`,
		active:   `SELECT 1, 'me', 'active', 0, 'select 1' WHERE 0`,
		kill:     func(int64) (string, []any) { return `SELECT 1`, nil },
	}}
	m.Open = func(_, _ string) (*sql.DB, error) { return sql.Open("sqlite", path) }
	h := fakehost.New(map[string]string{"secret://db": "pw"})
	ctx := context.Background()
	cfg, _ := json.Marshal(Config{Kind: "postgres", Host: "localhost", User: "ro", Password: "secret://db", Database: "app"})
	if err := m.Configure(ctx, h, "d", cfg); err != nil {
		t.Fatal(err)
	}
	if bad, _ := json.Marshal(Config{Kind: "postgres", Host: "localhost", User: "ro", Password: "plain", Database: "app"}); m.Configure(ctx, h, "x", bad) == nil {
		t.Fatal("plaintext password accepted")
	}
	run := func(action string, in any) (map[string]any, error) {
		b, _ := json.Marshal(in)
		r, err := m.Invoke(ctx, sdk.Call{Instance: "d", Action: action, Input: b})
		if err != nil {
			return nil, err
		}
		var out map[string]any
		_ = json.Unmarshal(r.Output, &out)
		return out, nil
	}
	out, err := run("query", map[string]string{"sql": "SELECT id, name FROM users ORDER BY id"})
	if err != nil {
		t.Fatal(err)
	}
	if rows := out["rows"].([]any); len(rows) != MaxRows || out["truncated"] != true {
		t.Fatalf("rows %d truncated %v", len(rows), out["truncated"])
	}
	if _, err := run("query", map[string]string{"sql": "DELETE FROM users"}); err == nil {
		t.Fatal("DELETE ran")
	}
	// A write that gets past the keyword check is still stopped by the
	// read-only transaction.
	if _, err := run("query", map[string]string{"sql": "WITH x AS (SELECT 1) INSERT INTO users SELECT 0, 'x' FROM x"}); err == nil {
		t.Fatal("write in a WITH ran")
	}
	if s, err := run("stats", nil); err != nil || s["sizeBytes"] != 4096.0 {
		t.Fatalf("stats %v %v", s, err)
	}
	r, err := m.Invoke(ctx, sdk.Call{Instance: "d", Action: "kill", Input: json.RawMessage(`{"id":42}`), DryRun: true})
	if err != nil || r.Plan == nil {
		t.Fatalf("kill dry run: %v", err)
	}
	if spec := findSpec(m, "query"); !spec.Sensitive || spec.Risk != sdk.RiskRead {
		t.Fatal("query must be a sensitive read")
	}
	if spec := findSpec(m, "kill"); spec.Risk != sdk.RiskDestructive {
		t.Fatal("kill must be destructive")
	}
}

func findSpec(m *Module, name string) sdk.ActionSpec {
	for _, a := range m.Manifest().Actions {
		if a.Name == name {
			return a
		}
	}
	return sdk.ActionSpec{}
}
