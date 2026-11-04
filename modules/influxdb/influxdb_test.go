package influxdb

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

const taskID = "0a1b2c3d4e5f6071"

type fake struct {
	mu      sync.Mutex
	seen    []string
	status  string
	queries []string
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/health" {
		io.WriteString(w, `{"name":"influxdb","message":"ready for queries and writes","status":"pass","version":"v2.7.10","commit":"abc"}`)
		return
	}
	if r.Header.Get("Authorization") != "Token itok" {
		w.WriteHeader(401)
		io.WriteString(w, `{"code":"unauthorized","message":"unauthorized access"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery+" "+string(body))
	q := r.URL.Query()
	switch r.Method + " " + r.URL.Path {
	case "GET /api/v2/orgs":
		if q.Get("org") != "home" {
			w.WriteHeader(404)
			io.WriteString(w, `{"code":"not found","message":"organization name \"x\" not found"}`)
			return
		}
		io.WriteString(w, `{"orgs":[{"id":"0123456789abcdef","name":"home"}]}`)
	case "GET /api/v2/buckets":
		io.WriteString(w, `{"buckets":[{"id":"b1","name":"telegraf","type":"user","retentionRules":[{"type":"expire","everySeconds":2592000}]},{"id":"b2","name":"_monitoring","type":"system"}]}`)
	case "POST /api/v2/query":
		var in struct {
			Query string `json:"query"`
		}
		json.Unmarshal(body, &in)
		f.queries = append(f.queries, in.Query)
		if strings.Contains(in.Query, "broken") {
			w.WriteHeader(400)
			io.WriteString(w, `{"code":"invalid","message":"compilation failed: error at @1:1-1:7: undefined identifier broken"}`)
			return
		}
		w.Header().Set("Content-Type", "text/csv")
		io.WriteString(w, ",result,table,_time,_value,host\r\n,_result,0,2026-11-04T10:00:00Z,12.5,web1\r\n,_result,0,2026-11-04T10:01:00Z,13,web1\r\n\r\n,result,table,_time,count\r\n,_result,1,2026-11-04T10:00:00Z,4\r\n\r\n")
	case "GET /api/v2/tasks":
		io.WriteString(w, `{"tasks":[{"id":"`+taskID+`","name":"downsample","status":"`+f.status+`","every":"1h","flux":"secret flux","latestCompleted":"2026-11-04T10:00:00Z","lastRunStatus":"failed","lastRunError":"could not write: token=abcdef1234567890 rejected"}]}`)
	case "GET /api/v2/tasks/" + taskID:
		io.WriteString(w, `{"id":"`+taskID+`","name":"downsample","status":"`+f.status+`","every":"1h"}`)
	case "PATCH /api/v2/tasks/" + taskID:
		var in struct {
			Status string `json:"status"`
		}
		json.Unmarshal(body, &in)
		f.status = in.Status
		io.WriteString(w, `{"id":"`+taskID+`","name":"downsample","status":"`+f.status+`"}`)
	case "GET /api/v2/tasks/" + taskID + "/runs":
		io.WriteString(w, `{"runs":[{"id":"r1","status":"success","scheduledFor":"2026-11-04T10:00:00Z"}]}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"code":"not found","message":"task not found"}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fake) {
	f := &fake{status: "active"}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: tok, Org: "home"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://i": "itok", "secret://bad": "nope"}), "i", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "i", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestReads(t *testing.T) {
	m, _ := setup(t, "secret://i")
	if h := m.Health(context.Background(), "i"); h.Status != "ok" || h.Message != "InfluxDB v2.7.10 · home" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"health", `{}`, `"status":"pass","version":"v2.7.10"`},
		{"buckets", `{}`, `"name":"telegraf","retentionSeconds":2592000`},
		{"query", `{"flux":"from(bucket: \"telegraf\") |> range(start: -1h) |> limit(n: 10)"}`, `"columns":["result","table","_time","_value","host","count"],"rows":[["_result","0","2026-11-04T10:00:00Z","12.5","web1",""],["_result","0","2026-11-04T10:01:00Z","13","web1",""],["_result","1","2026-11-04T10:00:00Z","","","4"]]`},
		{"tasks", `{}`, `"every":"1h","id":"` + taskID + `","lastRunError":"could not write: [redacted] rejected"`},
		{"task_runs", `{"id":"` + taskID + `"}`, `"status":"success"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
		if strings.Contains(string(r.Output), "secret flux") {
			t.Fatal("task flux returned")
		}
	}
	if _, err := invoke(m, "query", `{"flux":"broken"}`, false); err == nil || !strings.Contains(err.Error(), "couldn't run the query: compilation failed") {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if a.Name == "query" && (!a.Sensitive || a.Risk != sdk.RiskRead) {
			t.Fatal("query must be a sensitive read")
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "i"); h.Status != "down" || h.Message != "InfluxDB refused the token" {
		t.Fatalf("%+v", h)
	}
}

func TestTaskToggle(t *testing.T) {
	m, f := setup(t, "secret://i")
	r, err := invoke(m, "disable_task", `{"id":"`+taskID+`"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Disable task downsample ("+taskID+")" || f.status != "active" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "disable_task", `{"id":"`+taskID+`"}`, false)
	if err != nil || f.status != "inactive" || r.Undo == nil || r.Undo.Action != "enable_task" || string(r.Undo.Input) != `{"id":"`+taskID+`"}` {
		t.Fatalf("%+v %v %s", r, err, f.status)
	}
	// Already inactive: nothing changes and there's nothing to undo.
	r, err = invoke(m, "disable_task", `{"id":"`+taskID+`"}`, false)
	if err != nil || r.Undo != nil || !strings.Contains(string(r.Output), `"changed":false`) {
		t.Fatalf("%+v %v", r, err)
	}
	if r, _ := invoke(m, "disable_task", `{"id":"`+taskID+`"}`, true); !strings.Contains(r.Plan.Summary, "already inactive") {
		t.Fatal(r.Plan.Summary)
	}
	r, err = invoke(m, "enable_task", `{"id":"`+taskID+`"}`, false)
	if err != nil || f.status != "active" || r.Undo == nil || r.Undo.Action != "disable_task" {
		t.Fatalf("%+v %v", r, err)
	}
	for _, in := range []string{`{}`, `{"id":"../orgs"}`, `{"id":"0A1B2C3D4E5F6071"}`, `{"id":"` + taskID + `/runs"}`} {
		if _, err := invoke(m, "enable_task", in, false); err == nil {
			t.Fatalf("accepted %s", in)
		}
	}
	if _, err := invoke(m, "enable_task", `{"id":"ffffffffffffffff"}`, false); err == nil || !strings.Contains(err.Error(), "no task") {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if (a.Name == "enable_task" || a.Name == "disable_task") && (a.Risk != sdk.RiskWrite || !a.Reversible || !a.DryRun || a.Sensitive) {
			t.Fatal(a.Name)
		}
	}
}

func TestCheckFlux(t *testing.T) {
	for _, q := range []string{
		`from(bucket: "telegraf") |> range(start: -1h) |> filter(fn: (r) => r._measurement == "cpu" and r.host == "web1")`,
		"import \"strings\"\nimport \"influxdata/influxdb/schema\"\n\nschema.measurements(bucket: \"telegraf\")",
		"// top comment\nimport s \"strings\" // why\nfrom(bucket: \"b\") |> range(start: -1h) |> map(fn: (r) => ({r with host: s.toUpper(v: r.host)}))",
		`buckets()`,
		`from(bucket: "b") |> range(start: -1h) |> filter(fn: (r) => r.msg == "please send to(bucket) now")`,
		`from(bucket: "b") |> range(start: -1h) |> map(fn: (r) => ({from: r.a, to: r.b}))`,
		`import "experimental"` + "\n" + `from(bucket: "b") |> range(start: -1h) |> experimental.group(columns: ["host"], mode: "extend")`,
	} {
		if err := CheckFlux(q); err != nil {
			t.Errorf("%q: %v", q, err)
		}
	}
	for _, q := range []string{
		``, `   `,
		`from(bucket: "a") |> range(start: -1h) |> to(bucket: "b")`,
		`from(bucket: "a") |> range(start: -1h) |> to (bucket: "b")`,
		`w = to` + "\n" + `from(bucket: "a") |> range(start: -1h) |> w(bucket: "b")`,
		"import \"universe\"\nfrom(bucket: \"a\") |> range(start: -1h) |> universe.to(bucket: \"b\")",
		"import \"experimental\"\nfrom(bucket: \"a\") |> range(start: -1h) |> experimental.to(bucket: \"b\")",
		"import ex \"experimental\"\nfrom(bucket: \"a\") |> range(start: -1h) |> ex.to(bucket: \"b\")",
		"import \"http\"\nhttp.post(url: \"http://x\", data: bytes(v: \"x\"))",
		"import \"experimental/http\"\nhttp.get(url: \"http://169.254.169.254/\")",
		"import \"experimental/http/requests\"\nrequests.get(url: \"http://x\")",
		"import \"sql\"\nsql.to(driverName: \"postgres\", dataSourceName: \"x\", table: \"t\")",
		"import \"sql\"\nsql.from(driverName: \"postgres\", dataSourceName: \"x\", query: \"select 1\")",
		"import \"influxdata/influxdb/secrets\"\nsecrets.get(key: \"pw\")",
		"import \"slack\"\nslack.message(url: \"x\", channel: \"c\", text: \"t\")",
		"import \"contrib/sranka/telegram\"\ntelegram.message(token: \"x\", channel: \"c\", text: \"t\")",
		"import \"experimental/mqtt\"\nmqtt.publish(broker: \"tcp://x\", topic: \"t\", message: \"m\")",
		"import \"influxdata/influxdb/monitor\"\nmonitor.check()",
		"import \"csv\"\ncsv.from(file: \"/etc/passwd\")",
		"import \"experimental/csv\"\ncsv.from(url: \"http://x\")",
		"import \"experimental/prometheus\"\nprometheus.scrape(url: \"http://x\")",
		"import \"socket\"\nsocket.from(url: \"tcp://x\")",
		`from(bucket: "a", host: "https://other:8086", token: "t") |> range(start: -1h)`,
		`from(bucket: "a", org: "o", token: tok) |> range(start: -1h)`,
		`from(bucket: "a") |> range(start: -1h) |> filter(fn: (r) => r.a == "${to(bucket: "b")}")`,
		`from(bucket: "a") |> range(start: -1h) |> filter(fn: (r) => r.a == "unterminated`,
		"from(bucket: \"a\")\nimport \"http\"",
		`import "strings`,
		strings.Repeat("x", 40<<10),
	} {
		if err := CheckFlux(q); err == nil {
			t.Errorf("accepted %q", q)
		}
	}
}

func TestParseCSV(t *testing.T) {
	var b strings.Builder
	b.WriteString(",result,table,_value\r\n")
	for i := 0; i < MaxRows+10; i++ {
		b.WriteString(",_result,0,1\r\n")
	}
	cols, rows, truncated, err := ParseCSV(strings.NewReader(b.String()))
	if err != nil || len(cols) != 3 || len(rows) != MaxRows || !truncated {
		t.Fatal(len(cols), len(rows), truncated, err)
	}
	cols, rows, truncated, err = ParseCSV(strings.NewReader(""))
	if err != nil || len(cols) != 0 || len(rows) != 0 || truncated {
		t.Fatal(cols, rows, truncated, err)
	}
}

func TestConfigure(t *testing.T) {
	for _, c := range []Config{
		{URL: "ftp://x", Token: "secret://i", Org: "o"},
		{URL: "http://u:p@x:8086", Token: "secret://i", Org: "o"},
		{URL: "http://x:8086", Token: "plain", Org: "o"},
		{URL: "http://x:8086", Org: "o"},
		{URL: "http://x:8086", Token: "secret://i"},
		{URL: "https://x:8086", Token: "secret://i", Org: "o", Fingerprint: "zz"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
}

func TestRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") + "!" }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://i", Org: "home"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://i": "itok"}), "i", raw); err != nil {
		t.Fatal(err)
	}
	if _, err := invoke(m, "buckets", `{}`, false); err == nil || leaked != "" {
		t.Fatalf("followed the redirect: %v %q", err, leaked)
	}
}
