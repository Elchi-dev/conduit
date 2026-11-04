package clickhouse

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type fake struct {
	mu   sync.Mutex
	seen []string // raw query string + body
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-ClickHouse-User") != "reader" || r.Header.Get("X-ClickHouse-Key") != "pw1" {
		w.WriteHeader(516)
		io.WriteString(w, "Code: 516. DB::Exception: reader: Authentication failed: password is incorrect, or there is no user with such name. (AUTHENTICATION_FAILED) (version 24.8.1.1)\n")
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.seen = append(f.seen, r.URL.RawQuery+" | "+string(body))
	f.mu.Unlock()
	q := r.URL.Query()
	stmt := string(body)
	switch {
	case strings.HasPrefix(stmt, "SELECT version()"):
		io.WriteString(w, `{"meta":[{"name":"version()","type":"String"},{"name":"uptime()","type":"UInt32"}],"data":[["24.8.1.1",3600]],"rows":1}`)
	case strings.Contains(stmt, "system.databases"):
		io.WriteString(w, `{"meta":[],"data":[["default","Atomic"],["system","Atomic"]],"rows":2}`)
	case strings.Contains(stmt, "system.tables"):
		if strings.Contains(stmt, "{db:String}") && q.Get("param_db") != "app" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"meta":[],"data":[["app","events","MergeTree","120000","8400000"]],"rows":1}`)
	case strings.Contains(stmt, "system.query_log"):
		io.WriteString(w, `{"meta":[],"data":[["2026-11-04 10:00:00","5300","app","app","1000000","90000000","10","104857600","SELECT * FROM events WHERE email = 'ann@example.com'"]],"rows":1}`)
	case strings.HasPrefix(stmt, "INSERT"):
		// What a server with readonly=1 answers.
		w.Header().Set("X-ClickHouse-Exception-Code", "164")
		w.WriteHeader(500)
		io.WriteString(w, "Code: 164. DB::Exception: app: Cannot execute query in readonly mode. (READONLY) (version 24.8.1.1)\n")
	case strings.HasPrefix(stmt, "SELECT big"):
		rows := make([]string, 0, MaxRows+5)
		for i := 0; i < MaxRows+5; i++ {
			rows = append(rows, `[1]`)
		}
		io.WriteString(w, `{"meta":[{"name":"x","type":"UInt8"}],"data":[`+strings.Join(rows, ",")+`],"rows":1005,"rows_before_limit_at_least":5000}`)
	default:
		io.WriteString(w, `{"meta":[{"name":"n","type":"UInt64"}],"data":[["42"]],"rows":1,"statistics":{"elapsed":0.01,"rows_read":42,"bytes_read":336}}`)
	}
}

func setup(t *testing.T, pw string) (*Module, *fake) {
	f := &fake{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(Config{URL: srv.URL, Username: "reader", Password: pw, Database: "app"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://ch": "pw1", "secret://bad": "nope"}), "c", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "c", Action: action, Input: json.RawMessage(in)})
}

func TestReads(t *testing.T) {
	m, f := setup(t, "secret://ch")
	if h := m.Health(context.Background(), "c"); h.Status != "ok" || h.Message != "ClickHouse 24.8.1.1, up 3600s" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"databases", `{}`, `{"engine":"Atomic","name":"default"}`},
		{"tables", `{"database":"app"}`, `"bytes":"8400000","database":"app","engine":"MergeTree","name":"events","rows":"120000"`},
		{"query", `{"sql":"SELECT count() AS n FROM events"}`, `"rows":[["42"]],"rowsRead":42`},
		{"query", `{"sql":"SELECT big FROM t"}`, `"truncated":true`},
		{"slow_queries", `{"hours":2,"minMs":500,"limit":5}`, `"durationMs":"5300"`},
	} {
		r, err := invoke(m, c.action, c.in)
		if err != nil || !strings.Contains(string(r.Output), c.want) {
			t.Fatalf("%s %s: %.300s %v", c.action, c.in, r.Output, err)
		}
	}
	// Every request carries readonly=1, last, after the limits.
	for _, s := range f.seen {
		qs, _, _ := strings.Cut(s, " | ")
		if !strings.HasSuffix(qs, "&readonly=1") || !strings.Contains(qs, "max_execution_time=10") || !strings.Contains(qs, "max_result_rows=1000") || !strings.Contains(qs, "max_memory_usage=2147483648") || !strings.Contains(qs, "result_overflow_mode=break") {
			t.Fatal(s)
		}
	}
	last := f.seen[len(f.seen)-1]
	if !strings.Contains(last, "param_hours=2") || !strings.Contains(last, "param_min=500") || !strings.Contains(last, "LIMIT 5") {
		t.Fatal(last)
	}
	if !strings.Contains(f.seen[3], "database=app") {
		t.Fatal(f.seen[3])
	}
	for _, a := range m.Manifest().Actions {
		if (a.Name == "query" || a.Name == "slow_queries") && (!a.Sensitive || a.Risk != sdk.RiskRead) {
			t.Fatal(a.Name)
		}
		if a.Risk != sdk.RiskRead {
			t.Fatal("ClickHouse offers no writes:", a.Name)
		}
	}
}

func TestServerRefusal(t *testing.T) {
	m, _ := setup(t, "secret://ch")
	// Not reachable through query (the statement check refuses it first),
	// but a server-side refusal comes back as an error with its code.
	c, _ := m.set.Get("c")
	_, err := c.run(context.Background(), "INSERT INTO t VALUES (1)", "", nil)
	if err == nil || !strings.Contains(err.Error(), "ClickHouse error 164: app: Cannot execute query in readonly mode.") {
		t.Fatal(err)
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "c"); h.Status != "down" || !strings.Contains(h.Message, "refused the username or password") {
		t.Fatalf("%+v", h)
	}
}

func TestCheckStatement(t *testing.T) {
	for _, q := range []string{
		"SELECT 1", "select * from events where x = 'a; b' limit 5;", "WITH a AS (SELECT 1) SELECT * FROM a",
		"SHOW TABLES", "DESCRIBE TABLE events", "EXPLAIN SELECT 1", "EXISTS TABLE events",
		"SELECT formatDateTime(now(), '%F'), domain(url) FROM hits", "SELECT Settings FROM system.query_log LIMIT 1",
		"SELECT 'file(' AS s", // a false positive would be fine, but this one is stripped
		"-- comment\nSELECT 1 /* INSERT */",
	} {
		if err := CheckStatement(q); err != nil && q != "SELECT 'file(' AS s" {
			t.Errorf("%q: %v", q, err)
		}
	}
	for _, q := range []string{
		"", ";", "INSERT INTO t VALUES (1)", "ALTER TABLE t DELETE WHERE 1", "DROP TABLE t", "TRUNCATE t",
		"CREATE TABLE x AS SELECT 1", "SYSTEM SHUTDOWN", "KILL QUERY WHERE 1", "OPTIMIZE TABLE t", "SET readonly = 0",
		"SELECT 1; DROP TABLE t", "SELECT 1 /* unterminated", "SELECT 'unterminated",
		"SELECT * FROM url('http://169.254.169.254/latest', CSV)", "SELECT * FROM s3('https://b/x.csv')",
		"SELECT * FROM `url`('http://x')", `SELECT * FROM "file"('/etc/passwd')`, "SELECT * FROM file ('/etc/passwd')",
		"SELECT * FROM remote('other:9000', db.t)", "SELECT * FROM remoteSecure('o', db.t)",
		"SELECT * FROM mysql('h', 'd', 't', 'u', 'p')", "SELECT * FROM postgresql('h', 'd', 't', 'u', 'p')",
		"SELECT * FROM executable('x.sh', CSV, 'a String')", "SELECT * FROM hdfs('hdfs://x')", "SELECT * FROM jdbc('x')",
		"SELECT sleepEachRow(3) FROM numbers(10)", "SELECT sleep(3)",
		"SELECT 1 INTO OUTFILE '/tmp/x'", "SELECT 1 FORMAT TabSeparated", "SELECT 1 SETTINGS readonly = 0",
		"SELECT 1 SETTINGS max_execution_time=1000",
		"WITH x AS (SELECT 1) INSERT INTO t SELECT * FROM x",
	} {
		if err := CheckStatement(q); err == nil {
			t.Errorf("accepted %q", q)
		}
	}
}

func TestValidationAndConfig(t *testing.T) {
	m, f := setup(t, "secret://ch")
	for _, c := range []struct{ action, in string }{
		{"query", `{"sql":"DROP TABLE t"}`},
		{"query", `{"sql":"SELECT 1","database":"a b"}`},
		{"tables", `{"database":"x' OR 1=1 --"}`},
		{"slow_queries", `{"hours":0}`},
		{"slow_queries", `{"limit":1000}`},
		{"slow_queries", `{"minMs":-1}`},
		{"nope", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatal(f.seen)
	}
	for _, c := range []Config{{URL: "ftp://x"}, {URL: "http://u:p@x:8123"}, {URL: "http://x:8123", Password: "plain"}, {URL: "http://x:8123", Username: "a b"}, {URL: "http://x:8123", Database: "a;b"}, {URL: "https://x", Fingerprint: "zz"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
}

func TestRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("X-ClickHouse-Key") + "!" }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Username: "reader", Password: "secret://ch"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://ch": "pw1"}), "c", raw); err != nil {
		t.Fatal(err)
	}
	if _, err := invoke(m, "databases", `{}`); err == nil || leaked != "" {
		t.Fatalf("followed the redirect: %v %q", err, leaked)
	}
}
