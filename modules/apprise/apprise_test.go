package apprise

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
	mu       sync.Mutex
	seen     []string
	sent     []map[string]any
	extra    bool // a service added after the preview
	privacy0 bool
	always   bool // services tagged always and with both tags
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	if u, p, ok := r.BasicAuth(); !ok || u != "conduit" || p != "pw-good" {
		w.WriteHeader(401)
		return
	}
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	switch {
	case r.Method == "GET" && r.URL.Path == "/status":
		io.WriteString(w, `{"config_lock":false,"stateful_enabled":"simple","status":{"persistent_storage":true}}`)
	case r.Method == "GET" && r.URL.Path == "/json/urls/homelab":
		if r.URL.Query().Get("privacy") != "1" {
			f.privacy0 = true
		}
		urls := []string{`{"url":"tgram://LEAKMEbottoken/123","tags":["ops"]}`, `{"url":"mailto://user:LEAKMEpw@example.com","tags":["family"]}`}
		if f.extra {
			urls = append(urls, `{"url":"discord://LEAKME/abc","tags":["ops"]}`)
		}
		if f.always {
			urls = append(urls, `{"url":"ntfy://LEAKME/topic","tags":["Always"]}`, `{"url":"json://host/LEAKME","tags":["OPS","Family"]}`)
		}
		// The server's own filter reads a space as "or"; the module filters
		// itself and must always ask for every service.
		if r.URL.Query().Get("tag") != "all" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"tags":["family","ops"],"urls":[`+strings.Join(urls, ",")+`]}`)
	case r.Method == "GET" && r.URL.Path == "/json/urls/empty":
		w.WriteHeader(204)
	case r.Method == "POST" && r.URL.Path == "/notify/homelab":
		var b map[string]any
		json.Unmarshal(body, &b)
		f.sent = append(f.sent, b)
		io.WriteString(w, `{}`)
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, pw string) (*Module, *fake) {
	t.Helper()
	f := &fake{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Keys: []string{"homelab", "empty"}, Username: "conduit", Password: pw})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://pw": "pw-good", "secret://bad": "nope"}), "a", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "a", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestApprise(t *testing.T) {
	m, f := setup(t, "secret://pw")
	if h := m.Health(context.Background(), "a"); h.Status != "ok" || h.Message != "Apprise API · 2 configuration keys" {
		t.Fatalf("%+v", h)
	}
	r, err := invoke(m, "configs", `{}`, false)
	out := string(r.Output)
	if err != nil || !strings.Contains(out, `"kinds":["mailto","tgram"]`) || !strings.Contains(out, `"services":2`) || !strings.Contains(out, `"tags":["family","ops"]`) || strings.Contains(out, "LEAKME") || f.privacy0 {
		t.Fatalf("%s %v", out, err)
	}
	if !strings.Contains(out, `{"key":"empty","kinds":[],"services":0,"tags":[]}`) {
		t.Fatal(out)
	}

	in := `{"key":"homelab","tag":"ops","title":"Backup","body":"done","type":"success"}`
	r, err = invoke(m, "notify", in, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "1 services") || !strings.Contains(r.Plan.Summary, "tgram") || len(f.sent) != 0 || strings.Contains(string(r.Plan.Changes[0].After), "LEAKME") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "notify", in, false); err == nil || !strings.Contains(err.Error(), "expectedServices 1") || len(f.sent) != 0 {
		t.Fatal(err)
	}
	in = `{"key":"homelab","tag":"ops","title":"Backup","body":"done","type":"success","expectedServices":1}`
	f.extra = true
	if _, err := invoke(m, "notify", in, false); err == nil || !strings.Contains(err.Error(), "changed since the preview") || len(f.sent) != 0 {
		t.Fatal(err)
	}
	f.extra = false
	r, err = invoke(m, "notify", in, false)
	if err != nil || len(f.sent) != 1 || f.sent[0]["tag"] != "ops" || f.sent[0]["type"] != "success" || f.sent[0]["format"] != "text" {
		t.Fatalf("%s %v %v", r.Output, err, f.sent)
	}
	if _, err := invoke(m, "notify", `{"key":"homelab","tag":"nobody","body":"x","expectedServices":1}`, false); err == nil || !strings.Contains(err.Error(), "no service") || len(f.sent) != 1 {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if a.Name == "notify" && a.Risk != sdk.RiskDestructive {
			t.Fatal(a.Risk)
		}
	}
	f.always = true
	for tag, want := range map[string]string{"ops": "3 services", "ops family": "2 services", "ops, family": "4 services", "all": "4 services", "all ops": "3 services", "nobody": "1 services"} {
		r, err := invoke(m, "notify", `{"key":"homelab","tag":"`+tag+`","body":"x"}`, true)
		if err != nil || !strings.Contains(r.Plan.Summary, " "+want+" ") {
			t.Fatalf("%s: %+v %v", tag, r.Plan, err)
		}
	}
	f.always = false
	if s, _ := cleanTag(" a+b ,c "); s != "a b, c" {
		t.Fatal(s)
	}
}

func TestAppriseValidation(t *testing.T) {
	m, f := setup(t, "secret://pw")
	for _, in := range []string{
		`{}`, `{"key":"other","tag":"ops","body":"x"}`, `{"key":"../x","tag":"ops","body":"x"}`,
		`{"key":"homelab","body":"x"}`, `{"key":"homelab","tag":"a,,b","body":"x"}`, `{"key":"homelab","tag":"a&b","body":"x"}`,
		`{"key":"homelab","tag":"ops"}`, `{"key":"homelab","tag":"ops","body":"  "}`,
		`{"key":"homelab","tag":"ops","body":"` + strings.Repeat("x", maxBody+1) + `"}`,
		`{"key":"homelab","tag":"ops","body":"x","title":"` + strings.Repeat("t", maxTitle+1) + `"}`,
		`{"key":"homelab","tag":"ops","body":"x","type":"panic"}`, `{"key":"homelab","tag":"ops","body":"x","format":"rtf"}`,
		`{"key":"homelab","tag":"ops","body":"x","expectedServices":-1}`,
	} {
		if _, err := invoke(m, "notify", in, false); err == nil {
			t.Fatalf("accepted %s", in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{
		{URL: "https://a.example.com"}, {URL: "a.example.com", Keys: []string{"k"}}, {URL: "https://u:p@a.example.com", Keys: []string{"k"}},
		{URL: "https://a.example.com/?x=1", Keys: []string{"k"}}, {URL: "https://a.example.com", Keys: []string{"a/b"}},
		{URL: "https://a.example.com", Keys: []string{"k"}, Username: "u", Password: "plain"}, {URL: "https://a.example.com", Keys: []string{"k"}, Username: "u"},
		{URL: "https://a.example.com", Keys: []string{"k"}, Username: "u:x", Password: "secret://pw"},
		{URL: "https://a.example.com", Keys: []string{"k"}, Fingerprint: "zz"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "a"); h.Status != "down" || h.Message != "the Apprise server refused the username or password" {
		t.Fatalf("%+v", h)
	}
}

func TestAppriseRefusesCrossHostRedirect(t *testing.T) {
	var leaked bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _, leaked = r.BasicAuth() }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Keys: []string{"k"}, Username: "conduit", Password: "secret://pw"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://pw": "pw-good"}), "a", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "a"); h.Status != "down" || leaked || strings.Contains(h.Message, "pw-good") {
		t.Fatalf("followed the redirect: %+v %v", h, leaked)
	}
}
