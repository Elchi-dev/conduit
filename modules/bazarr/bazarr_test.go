package bazarr

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type fakeBazarr struct {
	mu        sync.Mutex
	seen      []string
	throttled bool
	running   bool
	started   string
}

func (f *fakeBazarr) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-API-KEY") != "bz_good" {
		w.WriteHeader(401)
		io.WriteString(w, `{"message":"Unauthorized"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	form, _ := url.ParseQuery(string(body))
	switch r.Method + " " + r.URL.Path {
	case "GET /bazarr/api/system/status":
		io.WriteString(w, `{"data":{"bazarr_version":"1.4.5","sonarr_version":"4.0.9","radarr_version":"5.11.0","bazarr_directory":"/app","start_time":1}}`)
	case "GET /bazarr/api/badges":
		n := 0
		if f.throttled {
			n = 1
		}
		fmt.Fprintf(w, `{"episodes":12,"movies":3,"providers":%d,"status":0,"announcements":0}`, n)
	case "GET /bazarr/api/system/health":
		io.WriteString(w, `{"data":[]}`)
	case "GET /bazarr/api/episodes/wanted":
		io.WriteString(w, `{"data":[{"seriesTitle":"Severance","episode_number":"2x01","episodeTitle":"Hello","missing_subtitles":[{"name":"English","code2":"en","forced":false,"hi":true}],"sonarrSeriesId":4,"sonarrEpisodeId":40}],"total":12}`)
	case "GET /bazarr/api/movies/wanted":
		io.WriteString(w, `{"data":[{"title":"Dune","missing_subtitles":[{"name":"German","code2":"de","forced":true}],"radarrId":8}],"total":3}`)
	case "GET /bazarr/api/movies/history":
		io.WriteString(w, `{"data":[{"title":"Dune","timestamp":"2 hours ago","description":"German subtitles downloaded from opensubtitlescom with a score of 93.3%.","language":{"name":"German","code2":"de"},"provider":"opensubtitlescom","score":"93.3%","action":1}],"total":1}`)
	case "GET /bazarr/api/providers":
		if f.throttled {
			io.WriteString(w, `{"data":[{"name":"opensubtitlescom","status":"TooManyRequests","retry":"in 2 hours"}]}`)
		} else {
			io.WriteString(w, `{"data":[]}`)
		}
	case "POST /bazarr/api/providers":
		if form.Get("action") == "reset" {
			f.throttled = false
		}
		w.WriteHeader(204)
	case "GET /bazarr/api/system/tasks":
		fmt.Fprintf(w, `{"data":[{"name":"Search for Missing Series Subtitles","interval":"every 6 hours","next_run_in":"in 2 hours","job_id":"wanted_search_missing_subtitles_series","job_running":%t}]}`, f.running)
	case "POST /bazarr/api/system/tasks":
		f.started = form.Get("taskid")
		w.WriteHeader(204)
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, ref string) (*Module, *fakeBazarr) {
	f := &fakeBazarr{throttled: true}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/bazarr/", APIKey: ref})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://bz": "bz_good", "secret://bad": "bz_bad"}), "b", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "b", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestBazarr(t *testing.T) {
	m, f := setup(t, "secret://bz")
	if h := m.Health(context.Background(), "b"); h.Status != "ok" || h.Message != "Bazarr 1.4.5 · 12 episodes and 3 movies missing subtitles, 1 providers throttled" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"status", `{}`, `"sonarr":"4.0.9"`},
		{"wanted", `{"kind":"series"}`, `"missing":["en (hearing impaired)"]`},
		{"wanted", `{"kind":"movies"}`, `"missing":["de (forced)"]`},
		{"history", `{"kind":"movies"}`, `"action":"downloaded"`},
		{"providers", `{}`, `"retry":"in 2 hours"`},
		{"tasks", `{}`, `"running":false`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "bz_good") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}

	r, err := invoke(m, "search_missing", `{"kind":"series"}`, true)
	if err != nil || r.Plan == nil || f.started != "" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "search_missing", `{"kind":"series"}`, false); err != nil || f.started != "wanted_search_missing_subtitles_series" {
		t.Fatal(err, f.started)
	}
	f.running, f.started = true, ""
	if r, err := invoke(m, "search_missing", `{"kind":"series"}`, false); err != nil || f.started != "" || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatal(string(r.Output), err)
	}
	if _, err := invoke(m, "search_missing", `{"kind":"movies"}`, false); err == nil || !strings.Contains(err.Error(), "Radarr") {
		t.Fatal(err)
	}

	r, err = invoke(m, "reset_providers", `{}`, true)
	if err != nil || r.Plan == nil || len(r.Plan.Changes) != 1 || !f.throttled {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "reset_providers", `{}`, false); err != nil || f.throttled {
		t.Fatal(err)
	}
	if r, _ := invoke(m, "reset_providers", `{}`, false); !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatal(string(r.Output))
	}
}

func TestBazarrValidation(t *testing.T) {
	m, f := setup(t, "secret://bz")
	for _, c := range []struct{ action, in string }{
		{"wanted", `{}`}, {"wanted", `{"kind":"../system"}`}, {"history", `{"kind":"music"}`}, {"search_missing", `{"kind":""}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{URL: "http://nas:6767", APIKey: "plain"}, {URL: "nas:6767", APIKey: "secret://bz"},
		{URL: "http://u:p@nas:6767", APIKey: "secret://bz"}, {URL: "http://nas:6767/?a=1", APIKey: "secret://bz"}, {URL: "http://nas:6767/#x", APIKey: "secret://bz"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "b"); h.Status != "down" || h.Message != "Bazarr refused the API key" {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(bad, "reset_providers", `{}`, false); err == nil || strings.Contains(err.Error(), "bz_bad") {
		t.Fatal(err)
	}
}

func TestBazarrRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("X-API-KEY") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, APIKey: "secret://bz"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://bz": "bz_good"}), "b", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "b"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
