package nzbget

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

type fakeNZBGet struct {
	mu     sync.Mutex
	seen   []string
	paused bool
	limit  int64 // bytes/s
	jobs   map[int]string
}

func (f *fakeNZBGet) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u, p, ok := r.BasicAuth()
	if !ok || u != "nzbget" || p != "pw_good" {
		w.WriteHeader(401)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Method != "POST" || r.URL.Path != "/jsonrpc" {
		w.WriteHeader(404)
		return
	}
	var call struct {
		Method string            `json:"method"`
		Params []json.RawMessage `json:"params"`
	}
	json.Unmarshal(body, &call)
	f.seen = append(f.seen, call.Method+" "+string(body))
	result := func(s string) { fmt.Fprintf(w, `{"version":"1.1","result":%s}`, s) }
	switch call.Method {
	case "version":
		result(`"24.3"`)
	case "status":
		result(fmt.Sprintf(`{"RemainingSizeMB":3000,"DownloadRate":2097152,"DownloadLimit":%d,"DownloadPaused":%t,"PostPaused":false,"FreeDiskSpaceMB":51200}`, f.limit, f.paused))
	case "listgroups":
		var gs []string
		for _, id := range []int{1, 2} {
			if st, ok := f.jobs[id]; ok {
				gs = append(gs, fmt.Sprintf(`{"NZBID":%d,"NZBName":"job-%d","Status":%q,"Category":"tv","FileSizeMB":1000,"RemainingSizeMB":250,"PausedSizeMB":0,"MaxPriority":0}`, id, id, st))
			}
		}
		gs = append(gs, `{"NZBID":3,"NZBName":"https://indexer.example/getnzb?id=5&apikey=LEAKMELEAKME","Status":"FETCHING","FileSizeMB":0}`)
		result("[" + strings.Join(gs, ",") + "]")
	case "history":
		result(`[{"NZBID":9,"Name":"show.s01e01","Status":"SUCCESS/ALL","Kind":"NZB","Category":"tv","FileSizeMB":700,"HistoryTime":1793700000,"DownloadTimeSec":60,"DestDir":"/dl/show"},
			{"NZBID":10,"Name":"movie","Status":"FAILURE/PAR","Kind":"URL","URL":"https://indexer.example/api?apikey=LEAKMELEAKME","FileSizeMB":4000}]`)
	case "pausedownload", "resumedownload":
		f.paused = call.Method == "pausedownload"
		result("true")
	case "editqueue":
		var cmd string
		var ids []int
		json.Unmarshal(call.Params[0], &cmd)
		json.Unmarshal(call.Params[2], &ids)
		for _, id := range ids {
			switch cmd {
			case "GroupPause":
				f.jobs[id] = "PAUSED"
			case "GroupResume":
				f.jobs[id] = "QUEUED"
			case "GroupDelete":
				delete(f.jobs, id)
			}
		}
		result("true")
	case "rate":
		var k int64
		json.Unmarshal(call.Params[0], &k)
		f.limit = k * 1024
		result("true")
	default:
		fmt.Fprint(w, `{"version":"1.1","error":{"name":"JSONRPCError","code":1,"message":"Invalid procedure"}}`)
	}
}

func setup(t *testing.T, ref string) (*Module, *fakeNZBGet) {
	f := &fakeNZBGet{jobs: map[int]string{1: "DOWNLOADING", 2: "PAUSED"}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/jsonrpc", Password: ref})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://nz": "pw_good", "secret://bad": "pw_bad"}), "n", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "n", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestNZBGet(t *testing.T) {
	m, f := setup(t, "secret://nz")
	if h := m.Health(context.Background(), "n"); h.Status != "ok" || h.Message != "NZBGet 24.3 · 3 jobs, downloading at 2048 KiB/s" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"queue", `{}`, `"progress":75`},
		{"queue", `{}`, `"speedLimitKiBs":"unlimited"`},
		{"queue", `{}`, `"freeDiskGB":50`},
		{"queue", `{}`, `"status":"paused"`},
		{"history", `{}`, `"completed":"2026-11-03T`},
		{"history", `{"failedOnly":true}`, `"status":"failure/par"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}
	if r, _ := invoke(m, "history", `{"failedOnly":true}`, false); strings.Contains(string(r.Output), "show.s01e01") {
		t.Fatal(string(r.Output))
	}

	// Whole queue: preview, pause, undo, no-op.
	r, err := invoke(m, "pause", `{}`, true)
	if err != nil || r.Plan == nil || f.paused {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = invoke(m, "pause", `{}`, false)
	if err != nil || !f.paused || r.Undo == nil || r.Undo.Action != "resume" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.paused {
		t.Fatal(err)
	}
	if r, err := invoke(m, "resume", `{}`, false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%s %v", r.Output, err)
	}

	// Single jobs: job 2 is already paused, so only job 1 changes.
	r, err = invoke(m, "pause", `{"jobs":[1,2]}`, false)
	if err != nil || f.jobs[1] != "PAUSED" || r.Undo == nil || string(r.Undo.Input) != `{"jobs":[1]}` {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.jobs[1] != "QUEUED" || f.jobs[2] != "PAUSED" {
		t.Fatal(err, f.jobs)
	}
	if _, err := invoke(m, "pause", `{"jobs":[42]}`, false); err == nil || !strings.Contains(err.Error(), "no job 42") {
		t.Fatal(err)
	}

	// Delete: preview changes nothing.
	r, err = invoke(m, "delete", `{"jobs":[2]}`, true)
	if err != nil || r.Plan == nil || len(r.Plan.Changes) != 1 || f.jobs[2] == "" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "delete", `{"jobs":[2]}`, false); err != nil || f.jobs[2] != "" {
		t.Fatal(err, f.jobs)
	}

	// Speed limit and its undo.
	r, err = invoke(m, "set_speed_limit", `{"kiBs":500}`, false)
	if err != nil || f.limit != 500*1024 || r.Undo == nil || string(r.Undo.Input) != `{"kiBs":0}` {
		t.Fatalf("%+v %v", r, err)
	}
	if r, _ := invoke(m, "set_speed_limit", `{"kiBs":500}`, false); r.Undo != nil {
		t.Fatal("no-op has an undo")
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.limit != 0 {
		t.Fatal(err)
	}

	risks := map[string]sdk.Risk{"pause": sdk.RiskDestructive, "delete": sdk.RiskDestructive, "resume": sdk.RiskWrite}
	for _, a := range m.Manifest().Actions {
		if want, ok := risks[a.Name]; ok && a.Risk != want {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestNZBGetValidation(t *testing.T) {
	m, f := setup(t, "secret://nz")
	for _, c := range []struct{ action, in string }{
		{"delete", `{}`},
		{"delete", `{"jobs":[0]}`},
		{"delete", `{"jobs":["1; drop"]}`},
		{"pause", `{"jobs":[-1]}`},
		{"pause", `{"jobs":[` + strings.Repeat("1,", 50) + `1]}`},
		{"set_speed_limit", `{}`},
		{"set_speed_limit", `{"kiBs":-5}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{URL: "http://nas:6789", Password: "plain"}, {URL: "nas:6789", Password: "secret://nz"},
		{URL: "http://u:p@nas:6789", Password: "secret://nz"}, {URL: "http://nas:6789/?x=1", Password: "secret://nz"}, {URL: "http://nas:6789", Username: "a:b", Password: "secret://nz"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "n"); h.Status != "down" || h.Message != "NZBGet refused the user name or password" || strings.Contains(h.Message, "pw_bad") {
		t.Fatalf("%+v", h)
	}
}

func TestNZBGetRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Password: "secret://nz"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://nz": "pw_good"}), "n", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "n"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}

// A job added by URL without a file name is named host plus path and query
// (no scheme), and its folder after it; Newznab links carry the key in r=.
func TestSafeNameSchemelessURL(t *testing.T) {
	for in, want := range map[string]string{
		"nzb.example/getnzb/abc.nzb&i=1234&r=0123456789abcdef0123456789abcdef": "nzb.example/getnzb/abc.nzb",
		"indexer.example/api?t=get&id=5&r=LEAKMELEAKME":                        "indexer.example/api",
		"/dl/nzb.example_getnzb_abc.nzb&i=1&r=LEAKMELEAKME":                    "/dl/nzb.example_getnzb_abc.nzb",
		"https://indexer.example/getnzb?id=5&apikey=LEAKMELEAKME":              "https://indexer.example/getnzb",
		"Show.S01E01.1080p_WEB_DL_GROUPNAME_LONG":                              "Show.S01E01.1080p_WEB_DL_GROUPNAME_LONG",
		"Tom & Jerry 1965":        "Tom & Jerry 1965",
		"movie @ indexer.example": "movie @ indexer.example",
	} {
		if got := safeName(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}
