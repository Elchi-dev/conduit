package gatus

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

type fakeGatus struct {
	mu   sync.Mutex
	seen []string
}

const statuses = `[
	{"name":"api","group":"core","key":"core_api","results":[
		{"status":200,"hostname":"api.example.com","duration":120000000,"success":true,"timestamp":"2026-11-04T10:00:00Z","conditionResults":[{"condition":"[STATUS] == 200","success":true}]},
		{"status":500,"hostname":"api.example.com","duration":45600000,"success":false,"timestamp":"2026-11-04T10:01:00Z","conditionResults":[{"condition":"[STATUS] (500) == 200","success":false}],
		 "errors":["Get \"https://admin:LEAKME@api.example.com/health?token=abcdefghijklmnopqrstuvwxyz\": EOF"]}],
	 "events":[{"type":"START","timestamp":"2026-11-04T09:00:00Z"},{"type":"UNHEALTHY","timestamp":"2026-11-04T10:01:00Z"}]},
	{"name":"site","group":"web","key":"web_site","results":[{"status":200,"duration":30000000,"success":true,"timestamp":"2026-11-04T10:01:00Z"}],"events":[]}]`

func (f *fakeGatus) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if u, p, ok := r.BasicAuth(); !ok || u != "ops" || p != "gatus-good" {
		w.WriteHeader(401)
		return
	}
	f.mu.Lock()
	f.seen = append(f.seen, r.URL.RequestURI())
	f.mu.Unlock()
	switch r.URL.Path {
	case "/api/v1/endpoints/statuses":
		io.WriteString(w, statuses)
	case "/api/v1/endpoints/core_api/statuses":
		var ss []json.RawMessage
		json.Unmarshal([]byte(statuses), &ss)
		w.Write(ss[0])
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, pw string) (*Module, *fakeGatus) {
	f := &fakeGatus{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Username: "ops", Password: pw})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://g": "gatus-good", "secret://bad": "nope"}), "g", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "g", Action: action, Input: json.RawMessage(in)})
}

func TestGatus(t *testing.T) {
	m, f := setup(t, "secret://g")
	if h := m.Health(context.Background(), "g"); h.Status != "degraded" || h.Message != "2 endpoints, 1 failing" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"endpoints", `{}`, `"successRate":50`},
		{"endpoints", `{}`, `"statusCode":500`},
		{"endpoints", `{"failingOnly":true}`, `"failedConditions":["[STATUS] (500) == 200"]`},
		{"endpoints", `{"group":"WEB"}`, `"key":"web_site"`},
		{"endpoint", `{"key":"core_api","limit":5}`, `"events":[{"time":"2026-11-04T10:01:00Z","type":"UNHEALTHY"}`},
		{"endpoint", `{"key":"core_api"}`, `"responseMs":45.6`},
	} {
		r, err := invoke(m, c.action, c.in)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") || strings.Contains(out, "abcdefghijklmnopqrstuvwxyz") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
	}
	if r, _ := invoke(m, "endpoints", `{"failingOnly":true}`); strings.Contains(string(r.Output), "web_site") {
		t.Fatal(string(r.Output))
	}
	if !strings.Contains(f.seen[len(f.seen)-1], "pageSize=20") {
		t.Fatal(f.seen)
	}
}

func TestGatusValidation(t *testing.T) {
	m, f := setup(t, "secret://g")
	for _, in := range []string{`{}`, `{"key":"../statuses"}`, `{"key":"a/b"}`, `{"key":"a?b=1"}`, `{"key":"a%2fb"}`, `{"key":".."}`, `{"key":"core_api","limit":500}`} {
		if _, err := invoke(m, "endpoint", in); err == nil {
			t.Fatalf("accepted %s", in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	if _, err := invoke(m, "endpoint", `{"key":"nope"}`); err == nil || !strings.Contains(err.Error(), "no endpoint") {
		t.Fatal(err)
	}
	for _, c := range []Config{
		{URL: "http://gatus:8080", Username: "ops", Password: "plain"},
		{URL: "http://gatus:8080", Token: "plain"},
		{URL: "http://gatus:8080", Username: "ops"},
		{URL: "gatus:8080"},
		{URL: "http://u:p@gatus:8080"},
		{URL: "http://gatus:8080/#x"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	raw, _ := json.Marshal(Config{URL: "http://gatus:8080"})
	if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err != nil {
		t.Fatal(err)
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "g"); h.Status != "down" || h.Message != "Gatus refused the credentials" {
		t.Fatalf("%+v", h)
	}
}

func TestGatusRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://t"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://t": "tok"}), "g", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "g"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
