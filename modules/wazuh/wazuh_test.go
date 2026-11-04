package wazuh

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

type fakeWazuh struct {
	mu        sync.Mutex
	seen      []string
	logins    int
	restarted []string
	failNext  bool
}

func (f *fakeWazuh) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path == "/security/user/authenticate" {
		if u, p, _ := r.BasicAuth(); u != "wazuh-wui" || p != "pw-good" {
			w.WriteHeader(401)
			io.WriteString(w, `{"title":"Unauthorized","detail":"Invalid credentials"}`)
			return
		}
		f.logins++
		io.WriteString(w, `{"data":{"token":"jwt-session-value"},"error":0}`)
		return
	}
	if r.Header.Get("Authorization") != "Bearer jwt-session-value" {
		w.WriteHeader(401)
		io.WriteString(w, `{"title":"Unauthorized","detail":"Invalid token"}`)
		return
	}
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
	agents := map[string]string{
		"001": `{"id":"001","name":"web-1","ip":"10.0.0.5","status":"active","version":"Wazuh v4.9.0","group":["default"],"node_name":"node01","lastKeepAlive":"2026-11-04T10:00:00Z","os":{"name":"Ubuntu","version":"24.04"}}`,
		"002": `{"id":"002","name":"db-1","ip":"10.0.0.6","status":"disconnected","version":"Wazuh v4.9.0","group":["default"],"os":{"name":"Debian","version":"12"}}`,
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /":
		io.WriteString(w, `{"data":{"title":"Wazuh API REST","api_version":"4.9.0"},"error":0}`)
	case "GET /agents/summary/status":
		io.WriteString(w, `{"data":{"connection":{"active":1,"disconnected":1,"never_connected":0,"pending":0,"total":2}},"error":0}`)
	case "GET /agents":
		var list []string
		if id := r.URL.Query().Get("agents_list"); id != "" {
			if a, ok := agents[id]; ok {
				list = append(list, a)
			}
		} else {
			list = []string{agents["001"], agents["002"]}
		}
		io.WriteString(w, `{"data":{"affected_items":[`+strings.Join(list, ",")+`],"total_affected_items":`+string(rune('0'+len(list)))+`},"error":0}`)
	case "PUT /agents/001/restart":
		if f.failNext {
			io.WriteString(w, `{"data":{"affected_items":[],"failed_items":[{"error":{"code":1707,"message":"Cannot send request, agent is not active"},"id":["001"]}]},"error":1}`)
			return
		}
		f.restarted = append(f.restarted, "001")
		io.WriteString(w, `{"data":{"affected_items":["001"],"total_affected_items":1,"failed_items":[]},"message":"Restart command was sent to all agents","error":0}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"title":"Not Found","detail":"not found"}`)
	}
}

type fakeIndexer struct {
	mu   sync.Mutex
	seen []string
}

func (f *fakeIndexer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if u, p, _ := r.BasicAuth(); u != "reader" || p != "idx-good" {
		w.WriteHeader(401)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.seen = append(f.seen, r.URL.Path+" "+string(body))
	f.mu.Unlock()
	switch r.URL.Path {
	case "/wazuh-alerts-*/_search":
		if strings.Contains(string(body), `"size":0`) {
			io.WriteString(w, `{"hits":{"total":{"value":42}},"aggregations":{
				"levels":{"buckets":[{"key":3,"doc_count":30},{"key":10,"doc_count":12}]},
				"rules":{"buckets":[{"key":"5710","doc_count":12,"top":{"hits":{"hits":[{"_source":{"rule":{"description":"sshd: Attempt to login using a non-existent user","level":10}}}]}}}]},
				"agents":{"buckets":[{"key":"web-1","doc_count":40}]}}}`)
			return
		}
		io.WriteString(w, `{"hits":{"total":{"value":1},"hits":[{"_source":{"timestamp":"2026-11-04T10:00:00Z","rule":{"id":"5710","level":10,"description":"sshd: non-existent user","groups":["sshd","authentication_failed"]},
			"agent":{"id":"001","name":"web-1"},"data":{"srcip":"198.51.100.9"},"location":"journald","full_log":"Failed password for invalid user admin from 198.51.100.9 password=LEAKMEhunter2secret \u001b[31m`+strings.Repeat("x", 900)+`"}}]}}`)
	case "/wazuh-states-vulnerabilities-*/_search":
		io.WriteString(w, `{"hits":{"total":{"value":7}},"aggregations":{"severity":{"buckets":[{"key":"High","doc_count":5},{"key":"Critical","doc_count":2}]},
			"cves":{"buckets":[{"key":"CVE-2024-6387","doc_count":2}]},"agents":{"buckets":[{"key":"web-1","doc_count":7}]}}}`)
	default:
		w.WriteHeader(404)
	}
}

var secrets = map[string]string{"secret://pw": "pw-good", "secret://bad": "pw-bad", "secret://idx": "idx-good"}

func setup(t *testing.T, pw string, indexer bool) (*Module, *fakeWazuh, *fakeIndexer) {
	f := &fakeWazuh{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	fi := &fakeIndexer{}
	isrv := httptest.NewServer(fi)
	t.Cleanup(isrv.Close)
	c := Config{URL: srv.URL, User: "wazuh-wui", Password: pw}
	if indexer {
		c.IndexerURL, c.IndexerUser, c.IndexerPassword = isrv.URL, "reader", "secret://idx"
	}
	m := New()
	raw, _ := json.Marshal(c)
	if err := m.Configure(context.Background(), fakehost.New(secrets), "w", raw); err != nil {
		t.Fatal(err)
	}
	return m, f, fi
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "w", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestWazuh(t *testing.T) {
	m, f, _ := setup(t, "secret://pw", true)
	if h := m.Health(context.Background(), "w"); h.Status != "ok" || h.Message != "Wazuh 4.9.0, 2 agents, 1 active, 1 disconnected" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"agents", `{}`, `"os":"Ubuntu 24.04"`},
		{"agents", `{}`, `"byStatus":{"active":1,"disconnected":1}`},
		{"alerts", `{}`, `"byLevel":{"10":12,"3":30}`},
		{"alerts", `{"minLevel":7,"agent":"1"}`, `"description":"sshd: Attempt to login using a non-existent user"`},
		{"recent_alerts", `{}`, `"srcip":"198.51.100.9"`},
		{"vulnerabilities", `{}`, `"bySeverity":{"Critical":2,"High":5,"Low":0,"Medium":0}`},
		{"vulnerabilities", `{"agent":"001"}`, `"topCves":[{"count":2,"name":"CVE-2024-6387"}]`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") || strings.Contains(out, "jwt-session-value") || strings.Contains(out, "idx-good") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}
	r, _ := invoke(m, "recent_alerts", `{}`, false)
	if strings.Contains(string(r.Output), `\u001b`) || len(r.Output) > 1500 {
		t.Fatalf("log line not cleaned: %s", r.Output)
	}

	// Restart: preview, real, refusals.
	r, err := invoke(m, "restart_agent", `{"agent":"001"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Changes[0].Target, "web-1") || len(f.restarted) != 0 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if r, err := invoke(m, "restart_agent", `{"agent":"1"}`, false); err != nil || len(f.restarted) != 1 || !strings.Contains(string(r.Output), `"restarted":true`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "restart_agent", `{"agent":"002"}`, false); err == nil || !strings.Contains(err.Error(), "disconnected") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "restart_agent", `{"agent":"009"}`, false); err == nil || !strings.Contains(err.Error(), "no agent") {
		t.Fatal(err)
	}
	f.failNext = true
	if _, err := invoke(m, "restart_agent", `{"agent":"001"}`, false); err == nil || !strings.Contains(err.Error(), "not active") {
		t.Fatal(err)
	}
	if f.logins != 1 {
		t.Fatalf("signed in %d times", f.logins)
	}
	for _, a := range m.Manifest().Actions {
		if a.Name == "restart_agent" && a.Risk != sdk.RiskDestructive || a.Name == "recent_alerts" && !a.Sensitive {
			t.Fatalf("%+v", a)
		}
	}
}

func TestWazuhValidation(t *testing.T) {
	m, f, fi := setup(t, "secret://pw", true)
	for _, c := range []struct{ action, in string }{
		{"restart_agent", `{}`}, {"restart_agent", `{"agent":"../x"}`}, {"restart_agent", `{"agent":"000"}`}, {"restart_agent", `{"agent":"0"}`},
		{"alerts", `{"hours":0.5}`}, {"alerts", `{"hours":10000}`}, {"alerts", `{"minLevel":20}`}, {"alerts", `{"agent":"web-1"}`},
		{"recent_alerts", `{"limit":500}`}, {"agents", `{"status":"x"}`}, {"vulnerabilities", `{"agent":"1 OR 1"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 || len(fi.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v %v", f.seen, fi.seen)
	}
	// Without the indexer, alerts explain what's missing.
	m2, _, _ := setup(t, "secret://pw", false)
	if _, err := invoke(m2, "alerts", `{}`, false); err == nil || !strings.Contains(err.Error(), "indexer") {
		t.Fatal(err)
	}
	if _, err := invoke(m2, "vulnerabilities", `{"agent":"001"}`, false); err == nil || !strings.Contains(err.Error(), "4.8") {
		t.Fatal(err)
	}
	for _, c := range []Config{
		{URL: "https://w:55000", User: "wazuh", Password: "plain"},
		{URL: "https://w:55000", Password: "secret://pw"},
		{URL: "https://u:p@w:55000", User: "wazuh", Password: "secret://pw"},
		{URL: "https://w:55000/?a=1", User: "wazuh", Password: "secret://pw"},
		{URL: "w:55000", User: "wazuh", Password: "secret://pw"},
		{URL: "https://w:55000", User: "wazuh", Password: "secret://pw", IndexerURL: "https://w:9200", IndexerUser: "admin", IndexerPassword: "plain"},
		{URL: "https://w:55000", User: "wazuh", Password: "secret://pw", IndexerUser: "admin", IndexerPassword: "secret://idx"},
		{URL: "https://w:55000", User: "wazuh", Password: "secret://pw", Fingerprint: "nope"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _, _ := setup(t, "secret://bad", false)
	if h := bad.Health(context.Background(), "w"); h.Status != "down" || h.Message != "Wazuh refused the API user and password" {
		t.Fatalf("%+v", h)
	}
}

func TestWazuhRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, User: "wazuh-wui", Password: "secret://pw"})
	if err := m.Configure(context.Background(), fakehost.New(secrets), "w", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "w"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
