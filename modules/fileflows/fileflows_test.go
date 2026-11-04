package fileflows

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

const token = "ff_token_good"

type fakeFileFlows struct {
	mu     sync.Mutex
	seen   []string
	nonces map[string]bool
	agent  bool // 26.09 and later: /api/agent
	prefix string
}

func (f *fakeFileFlows) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.Path)
	p := strings.TrimPrefix(r.URL.Path, f.prefix)
	if !strings.HasPrefix(p, "/api/") {
		fmt.Fprint(w, "<!DOCTYPE html><html></html>")
		return
	}
	ts, nonce := r.Header.Get("X-Timestamp"), r.Header.Get("X-Nonce")
	want := sign(token, r.Method+":"+p+":"+ts+":"+nonce+":")
	if r.Header.Get("X-Signature") != want || ts != "1793700000" || nonce == "" || f.nonces[nonce] || r.Header.Get("Authorization") != "" {
		w.WriteHeader(401)
		fmt.Fprint(w, "Invalid signature")
		return
	}
	f.nonces[nonce] = true
	switch p {
	case "/api/status":
		fmt.Fprint(w, `{"queue":7,"processing":1,"processed":120,"time":"1:02:03","processingFiles":[{"name":"/media/private/Family/holiday.mkv","relativePath":"Family/holiday.mkv","library":"Movies","step":"FFmpeg Builder","stepPercent":55.55}]}`)
	case "/api/agent":
		if !f.agent {
			fmt.Fprint(w, "<!DOCTYPE html><html></html>")
			return
		}
		fallthrough
	case "/api/node":
		fmt.Fprint(w, `[{"Uid":"a1","Name":"FileFlowsServer","Address":"FileFlowsServer","TempPath":"/temp/private","Enabled":true,"FlowRunners":2,"Version":"25.10.1","OperatingSystem":1}]`)
	case "/api/library":
		fmt.Fprint(w, `[{"Uid":"l1","Name":"Movies","Path":"/media/private/Movies","Enabled":true,"Flow":{"Uid":"f1","Name":"Video","Type":"FileFlows.Shared.Models.Flow"},"Priority":2,"ScanInterval":3600,"LastScanned":"2026-11-03T10:00:00.1234567"}]`)
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, ref, prefix string, agent bool) (*Module, *fakeFileFlows) {
	f := &fakeFileFlows{nonces: map[string]bool{}, agent: agent, prefix: prefix}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Now = func() time.Time { return time.Unix(1793700000, 0) }
	raw, _ := json.Marshal(Config{URL: srv.URL + prefix, APIToken: ref})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://ff": token, "secret://bad": "ff_token_bad"}), "f", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "f", Action: action, Input: json.RawMessage(in)})
}

func TestFileFlows(t *testing.T) {
	for _, c := range []struct {
		prefix string
		agent  bool
	}{{"", false}, {"/fileflows", true}} {
		m, _ := setup(t, "secret://ff", c.prefix, c.agent)
		if h := m.Health(context.Background(), "f"); h.Status != "ok" || h.Message != "FileFlows · 7 queued, 1 processing" {
			t.Fatalf("%+v", h)
		}
		for _, w := range []struct{ action, want string }{
			{"status", `"name":"holiday.mkv"`},
			{"status", `"percent":55.5`},
			{"nodes", `"runners":2`},
			{"libraries", `"flow":"Video"`},
			{"libraries", `"lastScanned":"2026-11-03T10:00:00Z"`},
		} {
			r, err := invoke(m, w.action, `{}`)
			out := string(r.Output)
			if err != nil || !strings.Contains(out, w.want) || strings.Contains(out, "private") || strings.Contains(out, "ff_token") {
				t.Fatalf("%s: %s %v", w.action, out, err)
			}
		}
	}
	m, _ := setup(t, "secret://ff", "", false)
	for _, a := range m.Manifest().Actions {
		if a.Risk != sdk.RiskRead {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestFileFlowsValidation(t *testing.T) {
	m, f := setup(t, "secret://ff", "", false)
	if _, err := invoke(m, "status", `{"x":`); err == nil {
		t.Fatal("accepted broken input")
	}
	if _, err := invoke(m, "pause", `{}`); err == nil {
		t.Fatal("accepted an unknown action")
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{URL: "http://nas:19200", APIToken: "plain"}, {URL: "http://nas:19200"}, {URL: "nas:19200", APIToken: "secret://ff"},
		{URL: "http://u:p@nas:19200", APIToken: "secret://ff"}, {URL: "http://nas:19200/?x=1", APIToken: "secret://ff"}, {URL: "http://nas:19200/#x", APIToken: "secret://ff"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad", "", false)
	if h := bad.Health(context.Background(), "f"); h.Status != "down" || h.Message != errAuth.Error() || strings.Contains(h.Message, "ff_token") {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(bad, "nodes", `{}`); err != errAuth {
		t.Fatal(err)
	}
}

func TestFileFlowsRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("X-Signature") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, APIToken: "secret://ff"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://ff": token}), "f", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "f"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}

// A server error naming a file loses the folder, and node fields FileFlows
// could send as objects aren't passed on.
func TestFileFlowsHidesPaths(t *testing.T) {
	fail := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail {
			w.WriteHeader(500)
			fmt.Fprint(w, `{"message":"Could not find '/media/private/Family/a.mkv'"}`)
			return
		}
		fmt.Fprint(w, `[{"Uid":"a1","Name":"n","OperatingSystem":{"TempPath":"/temp/private"},"Priority":"/private/x"}]`)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, APIToken: "secret://ff"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://ff": token}), "f", raw); err != nil {
		t.Fatal(err)
	}
	h := m.Health(context.Background(), "f")
	if h.Status != "down" || strings.Contains(h.Message, "private") || !strings.Contains(h.Message, "Could not find") {
		t.Fatalf("%+v", h)
	}
	fail = false
	r, err := invoke(m, "nodes", `{}`)
	if err != nil || strings.Contains(string(r.Output), "private") || !strings.Contains(string(r.Output), `"name":"n"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
}
