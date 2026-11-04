package rclone

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
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type job struct {
	finished, success, dry bool
	method                 string
}

type fakeRclone struct {
	mu      sync.Mutex
	methods []string
	bodies  []map[string]any
	jobs    map[int64]*job
	next    int64
	slow    bool   // dry runs never finish
	version string // core/version's answer, when not v1.68.1
}

func (f *fakeRclone) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u, p, ok := r.BasicAuth()
	if !ok || u != "conduit" || p != "rc-LEAKME" {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":"unauthorized"}`)
		return
	}
	if r.Method != "POST" || r.Header.Get("Content-Type") != "application/json" {
		w.WriteHeader(400)
		return
	}
	var b map[string]any
	json.NewDecoder(r.Body).Decode(&b)
	f.mu.Lock()
	defer f.mu.Unlock()
	m := strings.TrimPrefix(r.URL.Path, "/")
	f.methods = append(f.methods, m)
	f.bodies = append(f.bodies, b)
	id := func() int64 { n, _ := b["jobid"].(float64); return int64(n) }
	switch m {
	case "core/version":
		if f.version != "" {
			io.WriteString(w, f.version)
			return
		}
		io.WriteString(w, `{"version":"v1.68.1","os":"linux"}`)
	case "config/listremotes":
		io.WriteString(w, `{"remotes":["gdrive","b2","secret-remote"]}`)
	case "core/stats":
		if b["group"] == nil {
			io.WriteString(w, `{"bytes":10,"speed":1.5,"eta":null,"transfers":1,"transferring":[{"name":"LEAKME.pdf"}],"lastError":"LEAKME"}`)
			return
		}
		io.WriteString(w, `{"bytes":2048,"transfers":3,"deletes":2,"deletedDirs":1,"checks":9,"eta":5,"lastError":"LEAKME"}`)
	case "job/list":
		ids := []string{}
		for k := range f.jobs {
			ids = append(ids, fmt.Sprint(k))
		}
		fmt.Fprintf(w, `{"jobids":[%s]}`, strings.Join(ids, ","))
	case "job/status":
		j := f.jobs[id()]
		if j == nil {
			w.WriteHeader(500)
			io.WriteString(w, `{"error":"job not found","status":500}`)
			return
		}
		if j.dry && !f.slow {
			j.finished, j.success = true, true
		}
		fmt.Fprintf(w, `{"id":%d,"group":"job/%d","finished":%t,"success":%t,"error":"","startTime":"2026-11-04T10:00:00Z","duration":3.2,"output":{"LEAKME":1}}`, id(), id(), j.finished, j.success)
	case "job/stop":
		if j := f.jobs[id()]; j != nil {
			j.finished = true
		}
		io.WriteString(w, `{}`)
	case "operations/list":
		if b["fs"] != "gdrive:Docs" {
			w.WriteHeader(500)
			io.WriteString(w, `{"error":"directory not found"}`)
			return
		}
		io.WriteString(w, `{"list":[{"Path":"Docs/a.pdf","Name":"a.pdf","Size":5,"ModTime":"2026-11-01T00:00:00Z","IsDir":false,"Hashes":{"md5":"x"}},{"Path":"Docs/Old","Name":"Old","Size":-1,"IsDir":true}]}`)
	case "sync/sync", "sync/copy":
		f.next++
		cfg, _ := b["_config"].(map[string]any)
		f.jobs[f.next] = &job{dry: cfg["DryRun"] == true, method: m}
		fmt.Fprintf(w, `{"jobid":%d}`, f.next)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"error":"couldn't find method"}`)
	}
}

func setup(t *testing.T, mod func(*Config)) (*Module, *fakeRclone) {
	f := &fakeRclone{jobs: map[int64]*job{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	cfg := Config{URL: srv.URL, User: "conduit", Password: "secret://rc", LocalRoots: []string{"/srv/media"}, AllowedRemotes: []string{"gdrive", "b2"}}
	if mod != nil {
		mod(&cfg)
	}
	raw, _ := json.Marshal(cfg)
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://rc": "rc-LEAKME", "secret://bad": "nope"}), "r", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "r", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestRclone(t *testing.T) {
	old := pollEvery
	pollEvery = time.Millisecond
	defer func() { pollEvery = old }()
	m, f := setup(t, nil)
	if h := m.Health(context.Background(), "r"); h.Status != "ok" || h.Message != "rclone v1.68.1, 1 transfers running" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"remotes", `{}`, `{"allowed":false,"name":"secret-remote"}`},
		{"stats", `{}`, `"transferring":1`},
		{"list", `{"location":"gdrive:Docs"}`, `"name":"a.pdf"`},
		{"list", `{"location":"gdrive:Docs","limit":1}`, `"more":true`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}
	if _, err := invoke(m, "list", `{"location":"gdrive:Nope"}`, false); err == nil || !strings.Contains(err.Error(), "no folder") {
		t.Fatal(err)
	}

	// Sync: the preview runs rclone's dry run and reports its stats.
	in := `{"source":"/srv/media/photos","destination":"b2:backup/photos"}`
	r, err := invoke(m, "sync", in, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "delete 2 files and 1 folders") || !strings.Contains(r.Plan.Summary, "copy or update 3 files") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if j := f.jobs[1]; j == nil || !j.dry || j.method != "sync/sync" {
		t.Fatalf("dry run: %+v", j)
	}
	r, err = invoke(m, "sync", in, false)
	if err != nil || !strings.Contains(string(r.Output), `"job":2`) || f.jobs[2].dry {
		t.Fatalf("%s %v", r.Output, err)
	}
	last := f.bodies[len(f.bodies)-1]
	if last["srcFs"] != "/srv/media/photos" || last["dstFs"] != "b2:backup/photos" || last["_async"] != true || last["_config"] != nil {
		t.Fatal(last)
	}
	if r, err := invoke(m, "copy", `{"source":"gdrive:a","destination":"b2:a"}`, true); err != nil || r.Plan == nil || strings.Contains(r.Plan.Summary, "delete") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if r, err := invoke(m, "copy", `{"source":"gdrive:a","destination":"gdrive:a"}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%s %v", r.Output, err)
	}

	// Jobs and stopping one.
	if r, err := invoke(m, "jobs", `{}`, false); err != nil || !strings.Contains(string(r.Output), `"id":3`) || strings.Contains(string(r.Output), "LEAKME") {
		t.Fatalf("%s %v", r.Output, err)
	}
	if r, err := invoke(m, "job_status", `{"job":2}`, false); err != nil || !strings.Contains(string(r.Output), `"deletes":2`) || strings.Contains(string(r.Output), "LEAKME") {
		t.Fatalf("%s %v", r.Output, err)
	}
	if r, err := invoke(m, "stop_job", `{"job":2}`, true); err != nil || r.Plan == nil || f.jobs[2].finished {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "stop_job", `{"job":2}`, false); err != nil || !f.jobs[2].finished {
		t.Fatal(err)
	}
	if r, err := invoke(m, "stop_job", `{"job":2}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "job_status", `{"job":99}`, false); err == nil || !strings.Contains(err.Error(), "no rclone job 99") {
		t.Fatal(err)
	}

	// A dry run that doesn't finish in time is stopped and reported.
	f.slow = true
	oldWait := previewWait
	previewWait = 20 * time.Millisecond
	defer func() { previewWait = oldWait }()
	r, err = invoke(m, "sync", in, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "didn't finish") || !f.jobs[f.next].finished {
		t.Fatalf("%+v %v", r.Plan, err)
	}

	for _, meth := range f.methods {
		if !allowed[meth] || strings.HasPrefix(meth, "config/") && meth != "config/listremotes" {
			t.Fatalf("called %s", meth)
		}
	}
	for _, a := range m.Manifest().Actions {
		if (a.Name == "sync" || a.Name == "copy" || a.Name == "stop_job") && (a.Risk != sdk.RiskDestructive || !a.DryRun) {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestRcloneValidation(t *testing.T) {
	m, f := setup(t, nil)
	for _, c := range []struct{ action, in string }{
		{"list", `{}`},
		{"list", `{"location":"gdrive:../x"}`},
		{"list", `{"location":"gdrive:a/../../b"}`},
		{"list", `{"location":"/etc"}`},
		{"list", `{"location":"/srv/media/../../etc"}`},
		{"list", `{"location":"/srv/mediaX"}`},
		{"list", `{"location":"relative/path"}`},
		{"list", `{"location":":s3,access_key_id=x:bucket"}`},
		{"list", `{"location":"gdrive,client_id=x:a"}`},
		{"list", `{"location":"secret-remote:a"}`},
		{"list", `{"location":"C:\\Windows"}`},
		{"list", `{"location":"gdrive:a\nb"}`},
		{"sync", `{"source":"gdrive:a"}`},
		{"sync", `{"source":"gdrive:a","destination":"/etc"}`},
		{"copy", `{"source":"/root","destination":"b2:x"}`},
		{"stop_job", `{}`},
		{"stop_job", `{"job":-1}`},
		{"job_status", `{"job":0}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
		if len(f.methods) != 0 {
			t.Fatalf("%s %s reached the server", c.action, c.in)
		}
	}
	if len(f.methods) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.methods)
	}
	// A remote that isn't configured is checked against the server's list.
	m2, f2 := setup(t, func(c *Config) { c.AllowedRemotes = nil })
	if _, err := invoke(m2, "list", `{"location":"other:x"}`, false); err == nil || !strings.Contains(err.Error(), "no remote named") || len(f2.methods) != 1 {
		t.Fatalf("%v %v", err, f2.methods)
	}
	if _, err := invoke(m2, "list", `{"location":"/srv/x"}`, false); err == nil {
		t.Fatal("accepted a local path outside the roots")
	}
	for _, c := range []Config{{User: "u", Password: "plain"}, {URL: "localhost:5572", User: "u", Password: "secret://rc"}, {User: "", Password: "secret://rc"},
		{URL: "http://u:p@localhost:5572", User: "u", Password: "secret://rc"}, {URL: "http://localhost:5572/?x", User: "u", Password: "secret://rc"},
		{User: "u", Password: "secret://rc", LocalRoots: []string{"relative"}}, {User: "u", Password: "secret://rc", LocalRoots: []string{"/srv/../etc"}},
		{User: "u", Password: "secret://rc", AllowedRemotes: []string{":s3,x=y"}}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, func(c *Config) { c.Password = "secret://bad" })
	if h := bad.Health(context.Background(), "r"); h.Status != "down" || h.Message != "rclone refused the rc user name or password" {
		t.Fatalf("%+v", h)
	}
	if err := (&conn{}).rc(context.Background(), "config/dump", nil, nil); err == nil {
		t.Fatal("called a method off the list")
	}
	for _, meth := range []string{"core/command", "config/dump", "config/get", "backend/command", "options/set", "operations/purge", "operations/deletefile", "operations/delete"} {
		if allowed[meth] {
			t.Fatalf("%s is allowed", meth)
		}
	}
}

// An rclone older than v1.55 ignores _config: its "dry run" would sync for
// real, so the preview is refused before anything starts.
func TestRcloneDryRunNeedsV155(t *testing.T) {
	in := `{"source":"gdrive:a","destination":"b2:a"}`
	for _, v := range []string{`{"version":"v1.54.1","decomposed":[1,54,1]}`, `{"version":"v1.53.0"}`, `{"version":"LEAKME-custom"}`, `{}`} {
		m, f := setup(t, nil)
		f.version = v
		if _, err := invoke(m, "sync", in, true); err == nil || strings.Contains(err.Error(), "LEAKME") {
			t.Fatalf("%s: %v", v, err)
		}
		for _, meth := range f.methods {
			if strings.HasPrefix(meth, "sync/") {
				t.Fatalf("%s: started %s", v, meth)
			}
		}
	}
	for _, v := range []string{`{"version":"v1.55.0","decomposed":[1,55,0]}`, `{"version":"v1.69.0-beta.8443.2f0b1dd"}`, `{"version":"v2.0.0"}`} {
		m, f := setup(t, nil)
		f.version = v
		if r, err := invoke(m, "copy", in, true); err != nil || r.Plan == nil {
			t.Fatalf("%s: %v", v, err)
		}
	}
}

func TestRcloneRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, User: "conduit", Password: "secret://rc"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://rc": "rc-LEAKME"}), "r", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "r"); h.Status != "down" || leaked != "" || strings.Contains(h.Message, "LEAKME") {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
