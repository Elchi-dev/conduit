package tdarr

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type fakeTdarr struct {
	mu     sync.Mutex
	seen   []string
	paused map[string]bool
	ignore bool // keeps nodes as they were
}

func (f *fakeTdarr) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("x-api-key") != "tapi_good" {
		w.WriteHeader(401)
		fmt.Fprint(w, `{"message":"Invalid API key tapi_bad_echoed_back_here_xx"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.Path+" "+string(body))
	switch r.Method + " " + r.URL.Path {
	case "GET /api/v2/get-nodes":
		fmt.Fprintf(w, `{"n1":{"_id":"n1","nodeName":"basement","nodePaused":%t,"nodeVersion":"2.27.01","workerLimits":{"transcodecpu":2,"healthcheckcpu":1},
			"workers":{"w1":{"_id":"w1","file":"/media/private/Family/holiday.mkv","status":"Processing","percentage":42.37,"fps":"31","ETA":"0:10:00","job":{"type":"transcode"}}}},
			"n2":{"_id":"n2","nodeName":"attic","nodePaused":%t,"workers":{}}}`, f.paused["n1"], f.paused["n2"])
	case "POST /api/v2/update-node":
		var b struct {
			Data struct {
				NodeID      string `json:"nodeID"`
				NodeUpdates struct {
					NodePaused *bool `json:"nodePaused"`
				} `json:"nodeUpdates"`
			} `json:"data"`
		}
		json.Unmarshal(body, &b)
		if b.Data.NodeUpdates.NodePaused == nil {
			w.WriteHeader(400)
			return
		}
		if !f.ignore {
			f.paused[b.Data.NodeID] = *b.Data.NodeUpdates.NodePaused
		}
		fmt.Fprint(w, "OK")
	case "POST /api/v2/cruddb":
		switch {
		case strings.Contains(string(body), "StatisticsJSONDB"):
			fmt.Fprint(w, `{"_id":"statistics","table1Count":"10","table1ViewableCount":8,"table2Count":100,"table3Count":2,"table4Count":5,"table5Count":50,"table6Count":1,"sizeDiff":123.456}`)
		case strings.Contains(string(body), "LibrarySettingsJSONDB"):
			fmt.Fprint(w, `[{"_id":"L1","name":"Movies","folder":"/media/private/Movies","processLibrary":true,"folderWatching":true,"priority":1,"pluginStackType":"flow"}]`)
		default:
			w.WriteHeader(400)
		}
	case "POST /api/v2/stats/get-pies":
		if strings.Contains(string(body), `"L1"`) {
			fmt.Fprint(w, `{"pieStats":{"totalFiles":40,"totalTranscodeCount":12,"totalHealthCheckCount":30,"sizeDiff":20.5}}`)
		} else {
			fmt.Fprint(w, `{"pieStats":{"totalFiles":90,"totalTranscodeCount":20,"totalHealthCheckCount":70,"sizeDiff":123.456}}`)
		}
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, ref string) (*Module, *fakeTdarr) {
	f := &fakeTdarr{paused: map[string]bool{"n2": true}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, APIKey: ref})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://td": "tapi_good", "secret://bad": "tapi_bad"}), "t", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "t", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestTdarr(t *testing.T) {
	m, f := setup(t, "secret://td")
	if h := m.Health(context.Background(), "t"); h.Status != "ok" || h.Message != "Tdarr · 2 nodes, 1 workers running, 1 paused" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, want string }{
		{"nodes", `"file":"holiday.mkv"`},
		{"nodes", `"percent":42.4`},
		{"nodes", `"transcodecpu":2`},
		{"libraries", `"files":40`},
		{"libraries", `"spaceSavedGB":123.46`},
		{"queue", `"queued":13`},
		{"queue", `"transcode":{"done":100,"failed":2,"queued":8}`},
	} {
		r, err := invoke(m, c.action, `{}`, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "/media/private") || strings.Contains(out, "tapi_") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}

	// Preview, pause by name, undo, no-op.
	r, err := invoke(m, "pause_node", `{"node":"basement"}`, true)
	if err != nil || r.Plan == nil || f.paused["n1"] {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = invoke(m, "pause_node", `{"node":"Basement"}`, false)
	if err != nil || !f.paused["n1"] || r.Undo == nil || r.Undo.Action != "resume_node" || string(r.Undo.Input) != `{"node":"n1"}` {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.paused["n1"] {
		t.Fatal(err)
	}
	if r, err := invoke(m, "resume_node", `{"node":"n1"}`, false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "pause_node", `{"node":"garage"}`, false); err == nil || !strings.Contains(err.Error(), "no such node") {
		t.Fatal(err)
	}

	// A server that keeps the node as it was is reported, not trusted.
	f.ignore = true
	if _, err := invoke(m, "resume_node", `{"node":"attic"}`, false); err == nil || !strings.Contains(err.Error(), "kept node attic paused") {
		t.Fatal(err)
	}

	risks := map[string]sdk.Risk{"pause_node": sdk.RiskDestructive, "resume_node": sdk.RiskWrite}
	for _, a := range m.Manifest().Actions {
		if want, ok := risks[a.Name]; ok && a.Risk != want {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestTdarrValidation(t *testing.T) {
	m, f := setup(t, "secret://td")
	for _, c := range []struct{ action, in string }{
		{"pause_node", `{}`},
		{"pause_node", `{"node":"  "}`},
		{"resume_node", `{"node":"a\nb"}`},
		{"resume_node", `{"node":"` + strings.Repeat("x", 101) + `"}`},
		{"pause_node", `{"node":5}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{URL: "http://nas:8265", APIKey: "tapi_plain"}, {URL: "nas:8265"}, {URL: "ftp://nas:8265"},
		{URL: "http://u:p@nas:8265"}, {URL: "http://nas:8265/?x=1"}, {URL: "http://nas:8265/#x"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "t"); h.Status != "down" || h.Message != errKey.Error() || strings.Contains(h.Message, "tapi_") {
		t.Fatalf("%+v", h)
	}
	none, _ := setup(t, "")
	if _, err := invoke(none, "nodes", `{}`, false); err != errKey {
		t.Fatal(err)
	}
}

func TestTdarrRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("x-api-key") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, APIKey: "secret://td"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://td": "tapi_good"}), "t", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "t"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}

// A server error naming a file loses the folder before it's shown.
func TestTdarrErrorsHidePaths(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		fmt.Fprint(w, `{"message":"ENOENT: no such file, open '/media/private/Family/a.mkv' (C:\\private\\b)"}`)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL})
	if err := m.Configure(context.Background(), fakehost.New(nil), "t", raw); err != nil {
		t.Fatal(err)
	}
	h := m.Health(context.Background(), "t")
	if h.Status != "down" || strings.Contains(h.Message, "private") || !strings.Contains(h.Message, "ENOENT") {
		t.Fatalf("%+v", h)
	}
	if got := clip(strings.Repeat("é", 100), 101); len(got) > 104 || !strings.HasSuffix(got, "…") {
		t.Fatalf("%q", got)
	}
}
