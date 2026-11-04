package sabnzbd

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
	jobA = "SABnzbd_nzo_aaa111"
	jobB = "SABnzbd_nzo_bbb222"
	jobH = "SABnzbd_nzo_hist01"
	jobN = "SABnzbd_nzo_new999"
)

type fakeSab struct {
	mu      sync.Mutex
	seen    []string
	paused  bool
	jobs    map[string]string // id -> status
	hist    map[string]bool
	limit   string // speedlimit_abs in bytes/s
	lastAdd string
}

func (f *fakeSab) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path != "/sabnzbd/api" {
		w.WriteHeader(404)
		return
	}
	q := r.URL.Query()
	if q.Get("output") != "json" {
		io.WriteString(w, "error: need json\n")
		return
	}
	if q.Get("mode") == "version" {
		if q.Get("apikey") != "" {
			w.WriteHeader(500) // the key isn't sent where it isn't needed
			return
		}
		io.WriteString(w, `{"version":"4.3.2"}`)
		return
	}
	if q.Get("apikey") != "sabkey" {
		io.WriteString(w, `{"status":false,"error":"API Key Incorrect"}`)
		return
	}
	q.Del("apikey")
	f.seen = append(f.seen, q.Encode())
	ok := func() { io.WriteString(w, `{"status":true}`) }
	ids := strings.Split(q.Get("value"), ",")
	switch q.Get("mode") {
	case "queue":
		switch q.Get("name") {
		case "pause", "resume":
			for _, id := range ids {
				f.jobs[id] = map[string]string{"pause": "Paused", "resume": "Downloading"}[q.Get("name")]
			}
			ok()
			return
		case "delete":
			for _, id := range ids {
				delete(f.jobs, id)
			}
			ok()
			return
		}
		slots := []map[string]any{}
		for _, id := range []string{jobA, jobB, jobN} {
			if st, has := f.jobs[id]; has {
				slots = append(slots, map[string]any{"nzo_id": id, "filename": "Show." + id[12:], "status": st, "percentage": "42", "mb": "1024.5",
					"mbleft": "500.25", "timeleft": "0:10:00", "cat": "tv", "priority": "Normal"})
			}
		}
		limit := "100"
		if f.limit == "" {
			limit = "0"
		}
		json.NewEncoder(w).Encode(map[string]any{"queue": map[string]any{"status": map[bool]string{true: "Paused", false: "Downloading"}[f.paused],
			"paused": f.paused, "kbpersec": "2048.00", "mbleft": "500.25", "timeleft": "0:10:00", "speedlimit": limit, "speedlimit_abs": f.limit,
			"diskspace1": "120.5", "noofslots": len(slots), "slots": slots}})
	case "history":
		if q.Get("name") == "delete" {
			for _, id := range ids {
				delete(f.hist, id)
			}
			ok()
			return
		}
		slots := []map[string]any{}
		if f.hist[jobH] {
			slots = append(slots, map[string]any{"nzo_id": jobH, "name": "Movie.2024", "status": "Failed", "fail_message": "Download failed, apikey=LEAKMELEAKMELEAKME",
				"bytes": 2 << 30, "category": "movies", "completed": 1762000000, "download_time": 300, "storage": "/downloads/complete/Movie.2024",
				"url": "https://indexer.example/api?apikey=LEAKME"})
		}
		json.NewEncoder(w).Encode(map[string]any{"history": map[string]any{"noofslots": len(slots), "slots": slots}})
	case "pause", "resume":
		f.paused = q.Get("mode") == "pause"
		ok()
	case "addurl":
		f.lastAdd = q.Get("name")
		f.jobs[jobN] = "Queued"
		io.WriteString(w, `{"status":true,"nzo_ids":["`+jobN+`"]}`)
	case "config":
		v := q.Get("value")
		switch {
		case v == "0":
			f.limit = ""
		case strings.HasSuffix(v, "K"):
			f.limit = strings.TrimSuffix(v, "K") + "000" // close enough for the test: n*1000 bytes
		}
		ok()
	default:
		io.WriteString(w, `{"status":false,"error":"not implemented"}`)
	}
}

func setup(t *testing.T, key string) (*Module, *fakeSab) {
	f := &fakeSab{jobs: map[string]string{jobA: "Downloading", jobB: "Paused"}, hist: map[string]bool{jobH: true}, limit: "1048576"}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/sabnzbd/", APIKey: key})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://sab": "sabkey", "secret://bad": "nope"}), "s", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "s", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestSabnzbd(t *testing.T) {
	m, f := setup(t, "secret://sab")
	if h := m.Health(context.Background(), "s"); h.Status != "ok" || h.Message != "SABnzbd 4.3.2 · 2 jobs, downloading at 2048 KiB/s" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"queue", `{}`, `"speedLimitKiBs":1024`},
		{"queue", `{}`, `"progress":42`},
		{"history", `{}`, `"failure":"Download failed`},
		{"history", `{"failedOnly":true}`, `"path":"/downloads/complete/Movie.2024"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") || strings.Contains(out, "sabkey") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
	}

	// Pause the whole queue: preview, real, undo, nothing to change.
	r, err := invoke(m, "pause", `{}`, true)
	if err != nil || r.Plan == nil || f.paused {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "pause", `{}`, false)
	if err != nil || !f.paused || r.Undo == nil || r.Undo.Action != "resume" {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "pause", `{}`, false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.paused {
		t.Fatal(err)
	}
	// One job.
	r, err = invoke(m, "pause", `{"jobs":["`+jobA+`","`+jobB+`"]}`, false)
	if err != nil || f.jobs[jobA] != "Paused" || r.Undo == nil || string(r.Undo.Input) != `{"jobs":["`+jobA+`"]}` {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.jobs[jobA] != "Downloading" {
		t.Fatal(err)
	}

	// Add by URL: the indexer key stays out of the plan and the output.
	in := `{"url":"https://indexer.example/getnzb/1?apikey=LEAKME","category":"tv","priority":"high"}`
	r, err = invoke(m, "add_url", in, true)
	if b, _ := json.Marshal(r.Plan); err != nil || r.Plan == nil || strings.Contains(string(b), "LEAKME") || len(f.jobs) != 2 {
		t.Fatalf("%s %v", b, err)
	}
	r, err = invoke(m, "add_url", in, false)
	if err != nil || strings.Contains(string(r.Output), "LEAKME") || f.lastAdd != "https://indexer.example/getnzb/1?apikey=LEAKME" || r.Undo == nil || r.Undo.Action != "delete" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || len(f.jobs) != 2 {
		t.Fatal(err, f.jobs)
	}

	// Delete from the queue and history.
	r, err = invoke(m, "delete", `{"jobs":["`+jobB+`","`+jobH+`"],"deleteFiles":true}`, true)
	if err != nil || r.Plan == nil || len(r.Plan.Changes) != 2 || r.Plan.Changes[1].Target != "Movie.2024 (history)" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "delete", `{"jobs":["`+jobB+`","`+jobH+`"]}`, false); err != nil || len(f.jobs) != 1 || f.hist[jobH] {
		t.Fatal(err)
	}
	if _, err := invoke(m, "delete", `{"jobs":["`+jobB+`"]}`, false); err == nil || !strings.Contains(err.Error(), "no job") {
		t.Fatal(err)
	}

	// Speed limit.
	r, err = invoke(m, "set_speed_limit", `{"kiBs":0}`, false)
	if err != nil || f.limit != "" || r.Undo == nil || string(r.Undo.Input) != `{"kiBs":1024}` {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.limit == "" {
		t.Fatal(err)
	}
	if r, err := invoke(m, "set_speed_limit", `{"kiBs":1000}`, false); err != nil || r.Undo != nil {
		t.Fatalf("%s %v", r.Output, err)
	}
	for _, a := range m.Manifest().Actions {
		if (a.Name == "pause" || a.Name == "delete") && a.Risk != sdk.RiskDestructive {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestSabnzbdValidation(t *testing.T) {
	m, f := setup(t, "secret://sab")
	for _, c := range []struct{ action, in string }{
		{"pause", `{"jobs":["../api"]}`}, {"delete", `{}`}, {"delete", `{"jobs":["SABnzbd_nzo_a&mode=shutdown"]}`},
		{"add_url", `{}`}, {"add_url", `{"url":"file:///etc/passwd"}`}, {"add_url", `{"url":"https://x.example/a.nzb","priority":"urgent"}`},
		{"add_url", `{"url":"https://x.example/a.nzb","category":"a\nb"}`},
		{"set_speed_limit", `{}`}, {"set_speed_limit", `{"kiBs":-1}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{URL: "http://nas:8080", APIKey: "sabkey"}, {URL: "nas:8080", APIKey: "secret://sab"},
		{URL: "http://u:p@nas:8080", APIKey: "secret://sab"}, {URL: "http://nas:8080/?apikey=x", APIKey: "secret://sab"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "s"); h.Status != "down" || h.Message != "SABnzbd refused the API key" {
		t.Fatalf("%+v", h)
	}
}

func TestSabnzbdRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.URL.RawQuery }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.RequestURI(), http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, APIKey: "secret://sab"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://sab": "sabkey"}), "s", raw); err != nil {
		t.Fatal(err)
	}
	r, err := m.Invoke(context.Background(), sdk.Call{Instance: "s", Action: "queue"})
	if err == nil || strings.Contains(leaked, "sabkey") || strings.Contains(err.Error(), "sabkey") || leaked != "" {
		t.Fatalf("followed the redirect: %s %v %q", r.Output, err, leaked)
	}
}

// While SABnzbd fetches an NZB by URL the job is named after the URL, and a
// failed fetch lands in history named by it: the indexer's key mustn't show.
func TestSabnzbdHidesKeyInFetchNames(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		switch q.Get("mode") {
		case "queue":
			if q.Get("name") == "pause" {
				io.WriteString(w, `{"status":true}`)
				return
			}
			io.WriteString(w, `{"queue":{"status":"Downloading","noofslots":1,"slots":[{"nzo_id":"SABnzbd_nzo_grab01","status":"Grabbing",
				"filename":"Trying to fetch NZB from https://indexer.example/api?t=get&id=1&apikey=LEAKMEKEY"}]}}`)
		case "history":
			io.WriteString(w, `{"history":{"noofslots":2,"slots":[
				{"nzo_id":"SABnzbd_nzo_fail01","name":"https://indexer.example/api?t=get&id=1&apikey=LEAKMEKEY","status":"Failed","storage":"/dl/api?t=get&apikey=LEAKMEKEY"},
				{"nzo_id":"SABnzbd_nzo_fail02","name":"https://nzb.example/getnzb/abc.nzb&i=1&r=LEAKMEKEY","status":"Failed"}]}}`)
		default:
			io.WriteString(w, `{"status":true}`)
		}
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, APIKey: "secret://sab"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://sab": "sabkey"}), "s", raw); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ action, in, want string }{
		{"queue", `{}`, `Trying to fetch NZB from https://indexer.example/api`},
		{"history", `{}`, `"name":"https://nzb.example/getnzb/abc.nzb"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || strings.Contains(string(r.Output), "LEAKME") || !strings.Contains(string(r.Output), c.want) {
			t.Fatalf("%s: %s %v", c.action, r.Output, err)
		}
	}
	r, err := invoke(m, "pause", `{"jobs":["SABnzbd_nzo_grab01"]}`, true)
	if b, _ := json.Marshal(r.Plan); err != nil || r.Plan == nil || strings.Contains(string(b), "LEAKME") {
		t.Fatalf("%s %v", b, err)
	}
	if safeName("Show.S01E01.1080p_WEB_DL_GROUPNAME_LONG") != "Show.S01E01.1080p_WEB_DL_GROUPNAME_LONG" {
		t.Fatal("a plain name was changed")
	}
}

func TestSafeNameSchemeless(t *testing.T) {
	got := safeName("nzb.example/getnzb/abc.nzb&i=1234&r=0123456789abcdef0123456789abcdef")
	if strings.Contains(got, "0123456789abcdef") || strings.Contains(got, "i=1234") {
		t.Fatalf("key kept: %q", got)
	}
	if safeName("Tom & Jerry S01E01") != "Tom & Jerry S01E01" {
		t.Fatal("plain name changed")
	}
}
