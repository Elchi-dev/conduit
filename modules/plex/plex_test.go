package plex

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

type fakePlex struct {
	mu   sync.Mutex
	seen []string
}

func (f *fakePlex) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Plex-Token") != "plextok" {
		w.WriteHeader(401)
		return
	}
	f.mu.Lock()
	f.seen = append(f.seen, r.URL.Path+"?"+r.URL.RawQuery)
	f.mu.Unlock()
	switch r.URL.Path {
	case "/":
		io.WriteString(w, `{"MediaContainer":{"friendlyName":"Basement","version":"1.41.0"}}`)
	case "/library/sections":
		io.WriteString(w, `{"MediaContainer":{"Directory":[{"key":"1","title":"Movies","type":"movie"},{"key":"2","title":"TV","type":"show","refreshing":true}]}}`)
	case "/library/recentlyAdded", "/library/sections/2/recentlyAdded":
		io.WriteString(w, `{"MediaContainer":{"Metadata":[{"ratingKey":"9","type":"episode","grandparentTitle":"Show","parentTitle":"Season 1","title":"Pilot","librarySectionTitle":"TV","addedAt":1700000000}]}}`)
	case "/status/sessions":
		io.WriteString(w, `{"MediaContainer":{"Metadata":[{"type":"movie","title":"Heat","duration":1000,"viewOffset":250,"User":{"title":"sam"},"Player":{"title":"Living room","product":"Plex for Android","state":"playing"},"Session":{"id":"abc123"},"TranscodeSession":{"videoDecision":"transcode"}}]}}`)
	case "/library/sections/1/refresh", "/status/sessions/terminate":
		w.WriteHeader(200)
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, tok string) (*Module, *fakePlex) {
	f := &fakePlex{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	h := fakehost.New(map[string]string{"secret://plex": "plextok\n", "secret://bad": "x"})
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: tok})
	if err := m.Configure(context.Background(), h, "p", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "p", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestPlex(t *testing.T) {
	m, f := setup(t, "secret://plex")
	if h := m.Health(context.Background(), "p"); h.Status != "ok" || h.Message != "Basement 1.41.0" {
		t.Fatalf("%+v", h)
	}
	r, err := invoke(m, "libraries", `{}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"scanning":true`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "recent", `{"library":"2","limit":5}`, false)
	if err != nil || !strings.Contains(string(r.Output), "Show – Season 1 – Pilot") {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "sessions", `{}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"progress":25`) || !strings.Contains(string(r.Output), `"transcoding":true`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "refresh", `{"library":"1"}`, false); err != nil {
		t.Fatal(err)
	}
	r, err = invoke(m, "stop", `{"session":"abc123"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "sam watching Heat") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	for _, s := range f.seen {
		if strings.HasPrefix(s, "/status/sessions/terminate") {
			t.Fatal("dry run terminated")
		}
	}
	if _, err := invoke(m, "stop", `{"session":"abc123","message":"bedtime"}`, false); err != nil {
		t.Fatal(err)
	}
	if last := f.seen[len(f.seen)-1]; !strings.Contains(last, "reason=bedtime") || !strings.Contains(last, "sessionId=abc123") {
		t.Fatal(last)
	}
	if _, err := invoke(m, "stop", `{"session":"gone"}`, false); err == nil {
		t.Fatal("stopped a missing session")
	}
}

func TestPlexValidation(t *testing.T) {
	m, _ := setup(t, "secret://plex")
	for _, in := range []string{`{"library":"../1"}`, `{"library":"1/refresh?x"}`, `{"library":""}`} {
		if _, err := invoke(m, "refresh", in, false); err == nil {
			t.Fatalf("accepted %s", in)
		}
	}
	if _, err := invoke(m, "stop", `{"session":"a&b"}`, false); err == nil {
		t.Fatal("accepted session")
	}
	for _, c := range []Config{{URL: "http://plex:32400", Token: "plain"}, {URL: "plex:32400", Token: "secret://plex"}, {URL: "http://u:p@plex", Token: "secret://plex"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "p"); h.Status != "down" || !strings.Contains(h.Message, "token") {
		t.Fatalf("%+v", h)
	}
}
