//go:build dbintegration

package database

// Run against real databases (CI starts them as services):
//
//	CONDUIT_TEST_PG=localhost:5432 CONDUIT_TEST_MYSQL=localhost:3306 \
//	  go test -tags dbintegration ./modules/database
//
// Both use user "conduit", password "conduit", database "conduit".

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

func realDB(t *testing.T, kind, env string) (*Module, context.Context) {
	addr := os.Getenv(env)
	if addr == "" {
		t.Skip(env + " not set")
	}
	host, port, _ := net.SplitHostPort(addr)
	p, _ := strconv.Atoi(port)
	m := New()
	ctx := context.Background()
	cfg, _ := json.Marshal(Config{Kind: kind, Host: host, Port: p, User: "conduit", Password: "secret://db", Database: "conduit", TLS: "disable"})
	if err := m.Configure(ctx, fakehost.New(map[string]string{"secret://db": "conduit"}), "d", cfg); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(ctx, "d"); h.Status != "ok" {
		t.Fatalf("health %+v", h)
	}
	return m, ctx
}

func exercise(t *testing.T, m *Module, ctx context.Context, setup ...string) {
	run := func(action, in string) (string, error) {
		r, err := m.Invoke(ctx, sdk.Call{Instance: "d", Action: action, Input: json.RawMessage(in)})
		return string(r.Output), err
	}
	// The module can't create the table, so do it with a plain connection.
	db, err := m.open(ctx, mustConn(t, m))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range setup {
		if _, err := db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	for _, a := range []string{"tables", "stats", "active"} {
		if out, err := run(a, ""); err != nil {
			t.Fatalf("%s: %v", a, err)
		} else if a == "tables" && !strings.Contains(out, "things") {
			t.Fatalf("tables: %s", out)
		}
	}
	if out, err := run("query", `{"sql":"SELECT name FROM things"}`); err != nil || !strings.Contains(out, "lamp") {
		t.Fatalf("query: %s %v", out, err)
	}
	// Writes that slip past the keyword check fail in the read-only transaction.
	if _, err := run("query", `{"sql":"WITH x AS (SELECT 1 AS a) SELECT * FROM x FOR UPDATE"}`); err == nil {
		t.Log("FOR UPDATE allowed by this server in a read-only transaction")
	}
	if _, err := run("query", `{"sql":"SELECT 1; DELETE FROM things"}`); err == nil {
		t.Fatal("two statements ran")
	}
}

func mustConn(t *testing.T, m *Module) *conn {
	c, err := m.set.Get("d")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestPostgres(t *testing.T) {
	m, ctx := realDB(t, "postgres", "CONDUIT_TEST_PG")
	exercise(t, m, ctx, `CREATE TABLE IF NOT EXISTS things (name text)`, `INSERT INTO things VALUES ('lamp')`)
	// A data-modifying CTE is refused by the read-only transaction.
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "d", Action: "query", Input: json.RawMessage(`{"sql":"WITH d AS (DELETE FROM things RETURNING *) SELECT * FROM d"}`)}); err == nil {
		t.Fatal("DELETE inside WITH ran")
	}
}

func TestMySQL(t *testing.T) {
	m, ctx := realDB(t, "mysql", "CONDUIT_TEST_MYSQL")
	exercise(t, m, ctx, `CREATE TABLE IF NOT EXISTS things (name varchar(20))`, `INSERT INTO things VALUES ('lamp')`)
}
