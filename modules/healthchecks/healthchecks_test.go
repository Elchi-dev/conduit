package healthchecks

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

const (
	c1 = "11111111-2222-4333-8444-555555555551" // backup, up
	c2 = "11111111-2222-4333-8444-555555555552" // cron, down
	cn = "11111111-2222-4333-8444-555555555599" // created
)

type fake struct {
	mu     sync.Mutex
	seen   []string
	pings  []string
	checks map[string]map[string]any
	url    string
}

func newFake() *fake {
	return &fake{checks: map[string]map[string]any{
		c1: {"name": "Nightly backup", "slug": "backup", "tags": "prod db", "grace": 3600, "timeout": 86400, "n_pings": 40, "status": "up", "last_ping": "2026-11-04T03:00:00+00:00", "next_ping": "2026-11-05T03:00:00+00:00", "uuid": c1, "channels": "a,b", "desc": "pg_dump to S3"},
		c2: {"name": "Cron", "slug": "cron", "tags": "prod", "grace": 600, "schedule": "*/5 * * * *", "tz": "UTC", "n_pings": 2, "status": "down", "manual_resume": true, "uuid": c2, "channels": ""},
	}}
}

func (f *fake) view(id string) map[string]any {
	cp := map[string]any{}
	for k, v := range f.checks[id] {
		cp[k] = v
	}
	cp["ping_url"] = f.url + "/ping/" + id
	return cp
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	if strings.HasPrefix(r.URL.Path, "/ping/") {
		if r.Header.Get("X-Api-Key") != "" {
			w.WriteHeader(500)
			return
		}
		f.pings = append(f.pings, r.Method+" "+r.URL.Path+" "+string(body))
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/ping/"), "/")
		if ch := f.checks[parts[0]]; ch != nil {
			switch {
			case len(parts) == 1:
				ch["status"] = "up"
			case parts[1] == "fail":
				ch["status"] = "down"
			}
		}
		io.WriteString(w, "OK")
		return
	}
	key := r.Header.Get("X-Api-Key")
	if key != "hckey" && key != "rokey" {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":"wrong api key"}`)
		return
	}
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	path := strings.TrimPrefix(r.URL.Path, "/hc/api/v3")
	enc := json.NewEncoder(w)
	if key == "rokey" && !(r.Method == "GET" && path == "/checks/") {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":"wrong api key"}`)
		return
	}
	switch {
	case r.Method == "GET" && path == "/checks/":
		var list []any
		for _, id := range []string{c1, c2, cn} {
			if f.checks[id] == nil {
				continue
			}
			if tg := r.URL.Query().Get("tag"); tg != "" && !strings.Contains(" "+f.checks[id]["tags"].(string)+" ", " "+tg+" ") {
				continue
			}
			v := f.view(id)
			if key == "rokey" {
				delete(v, "uuid")
				delete(v, "ping_url")
				v["unique_key"] = "a1b2c3"
			}
			list = append(list, v)
		}
		enc.Encode(map[string]any{"checks": list})
	case r.Method == "POST" && path == "/checks/":
		var in map[string]any
		json.Unmarshal(body, &in)
		in["uuid"], in["status"], in["n_pings"] = cn, "new", 0
		f.checks[cn] = in
		w.WriteHeader(201)
		enc.Encode(f.view(cn))
	default:
		parts := strings.Split(strings.Trim(path, "/"), "/")
		if len(parts) < 2 || parts[0] != "checks" || f.checks[parts[1]] == nil {
			w.WriteHeader(404)
			io.WriteString(w, `{"error":"not found"}`)
			return
		}
		id := parts[1]
		switch {
		case r.Method == "GET" && len(parts) == 2:
			enc.Encode(f.view(id))
		case r.Method == "GET" && len(parts) == 3 && parts[2] == "flips":
			io.WriteString(w, `[{"timestamp":"2026-11-01T10:00:00+00:00","up":0},{"timestamp":"2026-11-01T10:05:00+00:00","up":1}]`)
		case r.Method == "POST" && len(parts) == 3 && parts[2] == "pause":
			f.checks[id]["status"] = "paused"
			enc.Encode(f.view(id))
		case r.Method == "POST" && len(parts) == 3 && parts[2] == "resume":
			if f.checks[id]["status"] != "paused" {
				w.WriteHeader(409)
				return
			}
			f.checks[id]["status"] = "new"
			enc.Encode(f.view(id))
		case r.Method == "DELETE" && len(parts) == 2:
			v := f.view(id)
			delete(f.checks, id)
			enc.Encode(v)
		default:
			w.WriteHeader(404)
		}
	}
}

func setup(t *testing.T, key string) (*Module, *fake) {
	t.Helper()
	f := newFake()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	f.url = srv.URL
	m := New()
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(Config{Address: srv.URL + "/hc", APIKey: key})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://hc": "hckey", "secret://ro": "rokey", "secret://bad": "nope"}), "h", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "h", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestHealthchecksReads(t *testing.T) {
	m, f := setup(t, "secret://hc")
	if h := m.Health(context.Background(), "h"); h.Status != "degraded" || h.Message != "2 checks · 1 down" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"checks", `{}`, `"byStatus":{"down":1,"up":1}`},
		{"checks", `{"tags":["db"]}`, `"check":"` + pid(t, m, c1) + `"`},
		{"check", `{"check":"` + strings.ToUpper(c1) + `"}`, `"integrations":2`},
		{"check", `{"check":"` + c2 + `"}`, `"schedule":"*/5 * * * *"`},
		{"flips", `{"check":"` + c1 + `","days":3}`, `"flips":[{"at":"2026-11-01T10:05:00+00:00","to":"up"},{"at":"2026-11-01T10:00:00+00:00","to":"down"}]`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) || strings.Contains(string(r.Output), "/ping/") || anyUUID.Match(r.Output) {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
	}
	if !strings.Contains(f.seen[2], "tag=db") || !strings.Contains(f.seen[len(f.seen)-1], "seconds=259200") {
		t.Fatal(f.seen)
	}
}

func TestHealthchecksWrites(t *testing.T) {
	m, f := setup(t, "secret://hc")

	r, err := invoke(m, "pause_check", `{"check":"`+c2+`"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "manual resume") || f.checks[c2]["status"] != "down" {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = invoke(m, "pause_check", `{"check":"`+c2+`"}`, false)
	if err != nil || f.checks[c2]["status"] != "paused" || r.Undo == nil || r.Undo.Action != "resume_check" {
		t.Fatalf("%+v %v", r, err)
	}
	if again, err := invoke(m, "pause_check", `{"check":"`+c2+`"}`, false); err != nil || again.Undo != nil || !strings.Contains(string(again.Output), "already paused") {
		t.Fatalf("%+v %v", again, err)
	}
	if u, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.checks[c2]["status"] != "new" || u.Undo.Action != "pause_check" {
		t.Fatalf("%+v %v", u, err)
	}

	// Ping: the preview warns, then the ping goes to the ping URL without the API key.
	r, err = invoke(m, "ping_check", `{"check":"`+c2+`"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "hides an outage") || len(f.pings) != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "ping_check", `{"check":"`+c2+`","signal":"fail","message":"disk full"}`, false); err != nil || f.checks[c2]["status"] != "down" || f.pings[0] != "POST /ping/"+c2+"/fail disk full" {
		t.Fatalf("%v %v", err, f.pings)
	}
	if _, err := invoke(m, "ping_check", `{"check":"`+c2+`"}`, false); err != nil || f.checks[c2]["status"] != "up" {
		t.Fatal(err)
	}

	in := `{"name":"Weekly report","schedule":"0 6 * * 1","tz":"Europe/Berlin","grace":600,"tags":["reports"],"allIntegrations":true}`
	if r, err := invoke(m, "create_check", in, true); err != nil || r.Plan == nil || f.checks[cn] != nil {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = invoke(m, "create_check", in, false)
	if err != nil || f.checks[cn] == nil || f.checks[cn]["channels"] != "*" || f.checks[cn]["tz"] != "Europe/Berlin" || r.Undo == nil || r.Undo.Action != "delete_check" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.checks[cn] != nil {
		t.Fatal(err)
	}
	if r, err := invoke(m, "delete_check", `{"check":"`+c1+`"}`, true); err != nil || r.Plan == nil || f.checks[c1] == nil || !strings.Contains(r.Plan.Summary, "40 pings") {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "delete_check", `{"check":"`+c1+`"}`, false); err != nil || f.checks[c1] != nil {
		t.Fatal(err)
	}

	risks := map[string]sdk.Risk{}
	for _, a := range m.Manifest().Actions {
		risks[a.Name] = a.Risk
	}
	if risks["ping_check"] != sdk.RiskDestructive || risks["delete_check"] != sdk.RiskDestructive || risks["pause_check"] != sdk.RiskWrite {
		t.Fatalf("%v", risks)
	}
}

func TestHealthchecksValidation(t *testing.T) {
	m, f := setup(t, "secret://hc")
	for _, c := range []struct{ action, in string }{
		{"check", `{"check":"../projects"}`},
		{"check", `{"check":"` + c1 + `/pause"}`},
		{"check", `{}`},
		{"checks", `{"tags":["a b"]}`},
		{"flips", `{"check":"` + c1 + `","days":365}`},
		{"pause_check", `{"check":"x"}`},
		{"ping_check", `{"check":"` + c1 + `","signal":"up"}`},
		{"ping_check", `{"check":"` + c1 + `","message":"` + strings.Repeat("x", 1001) + `"}`},
		{"create_check", `{"name":""}`},
		{"create_check", `{"name":"x","timeout":10}`},
		{"create_check", `{"name":"x","timeout":3600,"schedule":"* * * * *"}`},
		{"create_check", `{"name":"x","schedule":"$(rm -rf)"}`},
		{"create_check", `{"name":"x","schedule":"0 3 * * *","tz":"../etc"}`},
		{"create_check", `{"name":"x","tz":"UTC"}`},
		{"create_check", `{"name":"x","grace":1}`},
		{"delete_check", `{"check":"*"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 || len(f.pings) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{
		{APIKey: "plainkey"},
		{APIKey: "secret://hc", Address: "file:///etc"},
		{APIKey: "secret://hc", Address: "https://a:b@hc.example.com"},
		{APIKey: "secret://hc", Address: "https://hc.example.com/?x=1"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "h"); h.Status != "down" || h.Message != "Healthchecks refused the API key" {
		t.Fatalf("%+v", h)
	}
}

func TestHealthchecksReadOnlyKey(t *testing.T) {
	m, _ := setup(t, "secret://ro")
	r, err := invoke(m, "checks", `{}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"key":"a1b2c3"`) || !strings.Contains(string(r.Output), "read-only") {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "pause_check", `{"check":"`+c1+`"}`, false); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Fatal(err)
	}
}

func TestHealthchecksRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(Config{Address: srv.URL, APIKey: "secret://hc"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://hc": "hckey"}), "h", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "h"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}

// pid is the id the module shows a check by.
func pid(t *testing.T, m *Module, uuid string) string {
	t.Helper()
	c, err := m.set.Get("h")
	if err != nil {
		t.Fatal(err)
	}
	k, err := c.idKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return publicID(k, uuid)
}

// A check's UUID is its ping address (marking it up hides an outage): no
// output, preview, undo or error carries one; checks go by an instance-keyed
// id that actions resolve by listing.
func TestHealthchecksNoUUIDs(t *testing.T) {
	m, f := setup(t, "secret://hc")
	id1, id2 := pid(t, m, c1), pid(t, m, c2)
	if !idRe.MatchString(id1) || id1 == id2 {
		t.Fatal(id1, id2)
	}
	var outs []string
	run := func(action, in string, dry bool) sdk.Result {
		t.Helper()
		r, err := invoke(m, action, in, dry)
		if err != nil {
			t.Fatalf("%s %s: %v", action, in, err)
		}
		outs = append(outs, string(r.Output), string(mustJSON(r.Plan)), string(mustJSON(r.Undo)))
		return r
	}
	r := run("checks", `{}`, false)
	if !strings.Contains(string(r.Output), `"check":"`+id1+`"`) || !strings.Contains(string(r.Output), `"check":"`+id2+`"`) {
		t.Fatalf("%s", r.Output)
	}
	run("check", `{"check":"`+strings.ToUpper(id1)+`"}`, false)
	run("flips", `{"check":"`+id1+`"}`, false)
	r = run("pause_check", `{"check":"`+id2+`"}`, false)
	if f.checks[c2]["status"] != "paused" || string(r.Undo.Input) != `{"check":"`+id2+`"}` {
		t.Fatalf("%+v", r.Undo)
	}
	run(r.Undo.Action, string(r.Undo.Input), false)
	run("ping_check", `{"check":"`+id2+`","signal":"log"}`, true)
	run("ping_check", `{"check":"`+id2+`","signal":"log"}`, false)
	if f.pings[0] != "POST /ping/"+c2+"/log " {
		t.Fatal(f.pings)
	}
	r = run("create_check", `{"name":"New"}`, false)
	if string(r.Undo.Input) != `{"check":"`+pid(t, m, cn)+`"}` {
		t.Fatalf("%+v", r.Undo)
	}
	run(r.Undo.Action, string(r.Undo.Input), false)
	run("delete_check", `{"check":"`+id1+`"}`, true)
	for _, o := range outs {
		if anyUUID.MatchString(o) {
			t.Fatalf("a UUID came out: %s", o)
		}
	}
	// An unknown id, and errors that would carry a UUID.
	if _, err := invoke(m, "check", `{"check":"hc_`+strings.Repeat("0", 32)+`"}`, false); err == nil || anyUUID.MatchString(err.Error()) {
		t.Fatal(err)
	}
	delete(f.checks, c1)
	if _, err := invoke(m, "check", `{"check":"`+c1+`"}`, false); err == nil || anyUUID.MatchString(err.Error()) {
		t.Fatal(err)
	}
	// Another instance (or API key) names the same check differently.
	m2 := New()
	m2.HTTP = m.HTTP
	raw, _ := json.Marshal(Config{Address: f.url + "/hc", APIKey: "secret://hc"})
	if err := m2.Configure(context.Background(), fakehost.New(map[string]string{"secret://hc": "hckey"}), "other", raw); err != nil {
		t.Fatal(err)
	}
	c, _ := m2.set.Get("other")
	k, _ := c.idKey(context.Background())
	if publicID(k, c2) == id2 {
		t.Fatal("the id isn't keyed to the instance")
	}
}
