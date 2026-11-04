package consul

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type kv struct {
	val   []byte
	index uint64
}

type fake struct {
	mu           sync.Mutex
	seen         []string
	kv           map[string]*kv
	index        uint64
	deregistered []string
}

func (f *fake) pair(k string) map[string]any {
	e := f.kv[k]
	return map[string]any{"Key": k, "Value": base64.StdEncoding.EncodeToString(e.val), "Flags": 0, "CreateIndex": 1, "ModifyIndex": e.index}
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Consul-Token") != "ctok" {
		w.WriteHeader(403)
		io.WriteString(w, "ACL not found")
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	enc := json.NewEncoder(w)
	q := r.URL.Query()
	p := r.URL.EscapedPath()
	if strings.HasPrefix(p, "/v1/kv/") {
		key, _ := strings.CutPrefix(r.URL.Path, "/v1/kv/")
		cas, hasCAS := uint64(0), q.Has("cas")
		if hasCAS {
			cas, _ = strconv.ParseUint(q.Get("cas"), 10, 64)
		}
		switch r.Method {
		case "GET":
			if q.Has("keys") {
				var out []string
				for k := range f.kv {
					if strings.HasPrefix(k, key) {
						rest := strings.TrimPrefix(k, key)
						if i := strings.Index(rest, "/"); i >= 0 && q.Get("separator") == "/" {
							rest = rest[:i+1]
						}
						if !contains(out, key+rest) {
							out = append(out, key+rest)
						}
					}
				}
				enc.Encode(out)
				return
			}
			if f.kv[key] == nil {
				w.WriteHeader(404)
				return
			}
			enc.Encode([]any{f.pair(key)})
		case "PUT":
			cur := uint64(0)
			if f.kv[key] != nil {
				cur = f.kv[key].index
			}
			if hasCAS && cas != cur {
				io.WriteString(w, "false")
				return
			}
			f.index++
			f.kv[key] = &kv{val: body, index: f.index}
			io.WriteString(w, "true")
		case "DELETE":
			if hasCAS && (f.kv[key] == nil || f.kv[key].index != cas) {
				io.WriteString(w, "false")
				return
			}
			delete(f.kv, key)
			io.WriteString(w, "true")
		}
		return
	}
	switch r.Method + " " + p {
	case "GET /v1/status/leader":
		io.WriteString(w, `"10.0.0.1:8300"`)
	case "GET /v1/acl/token/self":
		io.WriteString(w, `{"Description":"ops","SecretID":"ctok"}`)
	case "GET /v1/agent/members":
		io.WriteString(w, `[{"Name":"s1","Addr":"10.0.0.1","Status":1,"Tags":{"role":"consul","dc":"dc1","build":"1.19.0"}},{"Name":"c1","Addr":"10.0.0.2","Status":4,"Tags":{"role":"node","dc":"dc1"}}]`)
	case "GET /v1/agent/self":
		io.WriteString(w, `{"Config":{"NodeName":"c1","Datacenter":"dc1"}}`)
	case "GET /v1/catalog/services":
		io.WriteString(w, `{"consul":[],"web":["v1"]}`)
	case "GET /v1/health/state/any":
		io.WriteString(w, `[{"Node":"c1","Name":"web http","Status":"critical","ServiceID":"web-1","ServiceName":"web"},{"Node":"c2","Name":"web http","Status":"passing","ServiceID":"web-2","ServiceName":"web"},{"Node":"c1","Name":"serf","Status":"passing"}]`)
	case "GET /v1/health/state/critical":
		io.WriteString(w, `[{"Node":"c1","Name":"web http","Status":"critical","Output":"connection refused","ServiceID":"web-1","ServiceName":"web"}]`)
	case "GET /v1/health/service/web":
		io.WriteString(w, `[{"Node":{"Node":"c1","Address":"10.0.0.2"},"Service":{"ID":"web-1","Service":"web","Port":80},"Checks":[{"Name":"web http","Status":"critical","ServiceID":"web-1"}]},
			{"Node":{"Node":"c2","Address":"10.0.0.3"},"Service":{"ID":"web-2","Service":"web","Port":80},"Checks":[]}]`)
	case "PUT /v1/agent/service/deregister/web-1":
		f.deregistered = append(f.deregistered, "agent web-1")
	case "PUT /v1/catalog/deregister":
		f.deregistered = append(f.deregistered, "catalog "+string(body))
	default:
		w.WriteHeader(404)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func setup(t *testing.T, tok string) (*Module, *fake) {
	f := &fake{kv: map[string]*kv{"config/app/db": {val: []byte("postgres://u:hunter2@db"), index: 5}, "config/app/port": {val: []byte("80"), index: 6}, "top": {val: []byte{0xff, 0x00}, index: 7}}, index: 10}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(Config{Address: srv.URL, Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://c": "ctok", "secret://bad": "nope"}), "c", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "c", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestConsulReads(t *testing.T) {
	m, _ := setup(t, "secret://c")
	if h := m.Health(context.Background(), "c"); h.Status != "ok" || h.Message != "leader 10.0.0.1:8300 · token ops" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"members", `{}`, `"role":"server","status":"alive"`},
		{"services", `{}`, `"checks":{"critical":1,"passing":1,"warning":0},"instances":2,"service":"web","status":"critical"`},
		{"service_health", `{"service":"web"}`, `"id":"web-2"`},
		{"checks", `{}`, `"output":"connection refused"`},
		{"kv_list", `{"prefix":"config/"}`, `"folders":["config/app/"]`},
		{"kv_list", `{"prefix":"config/","recurse":true}`, `"config/app/db"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) || strings.Contains(string(r.Output), "hunter2") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
	}
	r, err := invoke(m, "kv_get", `{"key":"config/app/db"}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"value":"postgres://u:hunter2@db"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	if r, _ := invoke(m, "kv_get", `{"key":"top"}`, false); !strings.Contains(string(r.Output), `"base64":"/wA="`) {
		t.Fatal(string(r.Output))
	}
	for _, a := range m.Manifest().Actions {
		if a.Name == "kv_get" && !a.Sensitive {
			t.Fatal("kv_get must be sensitive")
		}
	}
}

func TestConsulKVWrites(t *testing.T) {
	m, f := setup(t, "secret://c")
	r, err := invoke(m, "kv_put", `{"key":"config/app/db","value":"postgres://u:n3w@db"}`, true)
	if err != nil || r.Plan == nil || string(f.kv["config/app/db"].val) != "postgres://u:hunter2@db" {
		t.Fatalf("%+v %v", r, err)
	}
	plan, _ := json.Marshal(r.Plan)
	if strings.Contains(string(plan), "hunter2") || strings.Contains(string(plan), "n3w") || !strings.Contains(r.Plan.Summary, "23 bytes → 19 bytes") {
		t.Fatalf("%s", plan)
	}
	r, err = invoke(m, "kv_put", `{"key":"config/app/db","value":"postgres://u:n3w@db"}`, false)
	if err != nil || string(f.kv["config/app/db"].val) != "postgres://u:n3w@db" || r.Undo == nil || r.Undo.Action != "kv_put" {
		t.Fatalf("%+v %v", r, err)
	}
	if !strings.Contains(f.seen[len(f.seen)-2], "cas=5") {
		t.Fatal(f.seen)
	}
	undo := string(r.Undo.Input)
	if _, err := invoke(m, "kv_put", undo, false); err != nil || string(f.kv["config/app/db"].val) != "postgres://u:hunter2@db" {
		t.Fatal(err)
	}
	// The same undo again: the key moved on.
	if _, err := invoke(m, "kv_put", undo, false); err == nil || !strings.Contains(err.Error(), "changed since") {
		t.Fatal(err)
	}
	// A new key's undo deletes it.
	r, err = invoke(m, "kv_put", `{"key":"config/new","value":"x"}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "kv_delete" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.kv["config/new"] != nil {
		t.Fatal(err)
	}
	// Binary values round-trip through delete and its undo.
	r, err = invoke(m, "kv_delete", `{"key":"top"}`, false)
	if err != nil || f.kv["top"] != nil || r.Undo == nil {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || string(f.kv["top"].val) != "\xff\x00" {
		t.Fatal(err)
	}
	if _, err := invoke(m, "kv_put", `{"key":"top","value":"x","cas":0}`, false); err == nil {
		t.Fatal("cas 0 on an existing key accepted")
	}
}

func TestConsulDeregister(t *testing.T) {
	m, f := setup(t, "secret://c")
	if _, err := invoke(m, "deregister_service", `{"service":"web"}`, true); err == nil || !strings.Contains(err.Error(), "2 instances") {
		t.Fatal(err)
	}
	r, err := invoke(m, "deregister_service", `{"service":"web","id":"web-1"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "through its agent") || len(f.deregistered) != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "deregister_service", `{"service":"web","id":"web-1"}`, false); err != nil || f.deregistered[0] != "agent web-1" {
		t.Fatalf("%v %v", f.deregistered, err)
	}
	r, _ = invoke(m, "deregister_service", `{"service":"web","node":"c2"}`, true)
	if !strings.Contains(r.Plan.Summary, "adds it back") {
		t.Fatal(r.Plan.Summary)
	}
	if _, err := invoke(m, "deregister_service", `{"service":"web","node":"c2"}`, false); err != nil || !strings.Contains(f.deregistered[1], `"ServiceID":"web-2"`) {
		t.Fatalf("%v %v", f.deregistered, err)
	}
	for _, a := range m.Manifest().Actions {
		switch a.Name {
		case "deregister_service", "kv_delete":
			if a.Risk != sdk.RiskDestructive || !a.DryRun {
				t.Fatal(a.Name)
			}
		case "kv_put":
			if a.Risk != sdk.RiskWrite || !a.DryRun || !a.Reversible || !a.Sensitive {
				t.Fatal(a.Name)
			}
		}
	}
}

func TestConsulValidation(t *testing.T) {
	m, f := setup(t, "secret://c")
	for _, c := range []struct{ action, in string }{
		{"service_health", `{"service":"../agent/self"}`},
		{"service_health", `{"service":"web?x=1"}`},
		{"service_health", `{"service":"web","datacenter":"dc1&x"}`},
		{"checks", `{"state":"../../x"}`},
		{"kv_get", `{"key":"../acl/tokens"}`},
		{"kv_get", `{"key":"a/../../b"}`},
		{"kv_get", `{"key":"a?recurse"}`},
		{"kv_get", `{"key":""}`},
		{"kv_get", `{"key":"a//b"}`},
		{"kv_list", `{"prefix":"../x/"}`},
		{"kv_put", `{"key":"a"}`},
		{"kv_put", `{"key":"a","value":"!!","base64":true}`},
		{"kv_put", `{"key":"a/","value":"x"}`},
		{"kv_delete", `{"key":"a#b"}`},
		{"deregister_service", `{"service":"web","id":"../../x"}`},
		{"deregister_service", `{"service":"web","node":"a/b"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{Address: "http://x:8500", Token: "plain"}, {Address: "ftp://x"}, {Address: "http://u:p@x:8500"}, {Address: "http://x:8500/v1"}, {Address: "http://x", Datacenter: "a/b"}, {Address: "https://x", Fingerprint: "zz"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "c"); h.Status != "down" {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(bad, "members", `{}`, false); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatal(err)
	}
}

func TestConsulRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("X-Consul-Token") + "!" }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{Address: srv.URL, Token: "secret://c"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://c": "ctok"}), "c", raw); err != nil {
		t.Fatal(err)
	}
	if _, err := invoke(m, "members", `{}`, false); err == nil || leaked != "" {
		t.Fatalf("followed the redirect: %v %q", err, leaked)
	}
}
