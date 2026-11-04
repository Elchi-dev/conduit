package arr

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

type fakeArr struct {
	app     string // "Sonarr", "Radarr", "Prowlarr"
	api     string
	mu      sync.Mutex
	seen    []string
	added   map[string]any
	deleted string
	library map[int]string
}

func (f *fakeArr) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Api-Key") != "key1" {
		w.WriteHeader(401)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	p := strings.TrimPrefix(r.URL.Path, "/sonarr")
	if !strings.HasPrefix(p, f.api) {
		w.WriteHeader(404)
		return
	}
	p = strings.TrimPrefix(p, f.api)
	q := r.URL.Query()
	switch r.Method + " " + p {
	case "GET /system/status":
		fmt.Fprintf(w, `{"appName":%q,"version":"4.0.10","osName":"debian","isDocker":true,"startTime":"2026-11-01T00:00:00Z"}`, f.app)
	case "GET /health":
		io.WriteString(w, `[{"source":"IndexerStatusCheck","type":"warning","message":"Indexers unavailable due to failures: NZBgeek","wikiUrl":"https://wiki.servarr.com/x"}]`)
	case "GET /queue":
		if q.Get("includeSeries") != "true" || q.Get("pageSize") != "50" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"totalRecords":1,"records":[{"id":7,"title":"Show.S01E02.1080p","status":"downloading","trackedDownloadStatus":"warning","trackedDownloadState":"downloading","size":1048576000,"sizeleft":262144000,"timeleft":"00:10:00","downloadClient":"qBittorrent","protocol":"torrent","series":{"title":"The Show"},"episode":{"seasonNumber":1,"episodeNumber":2,"title":"Two"},"statusMessages":[{"title":"x","messages":["Stalled"]}]}]}`)
	case "GET /calendar":
		if q.Get("start") != "2026-11-04T00:00:00Z" || q.Get("end") != "2026-11-11T12:00:00Z" || q.Get("unmonitored") != "false" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `[{"seriesId":1,"seasonNumber":2,"episodeNumber":1,"title":"Back","airDateUtc":"2026-11-06T02:00:00Z","hasFile":false,"monitored":true,"series":{"title":"The Show"}},
			{"seriesId":2,"seasonNumber":1,"episodeNumber":5,"title":"Early","airDateUtc":"2026-11-05T02:00:00Z","hasFile":true,"monitored":true,"series":{"title":"Other"}}]`)
	case "GET /wanted/missing":
		if f.app == "Radarr" {
			w.WriteHeader(404)
			return
		}
		io.WriteString(w, `{"totalRecords":1,"records":[{"seriesId":1,"seasonNumber":1,"episodeNumber":1,"title":"Pilot","airDateUtc":"2026-01-01T00:00:00Z","series":{"title":"The Show"}}]}`)
	case "GET /series", "GET /movie":
		var items []string
		for id, t := range f.library {
			items = append(items, fmt.Sprintf(`{"id":%d,"title":%q,"year":2020,"monitored":true,"hasFile":false,"isAvailable":true,"statistics":{"episodeFileCount":3,"episodeCount":10,"sizeOnDisk":5368709120},"path":"/tv/x"}`, id, t))
		}
		io.WriteString(w, "["+strings.Join(items, ",")+"]")
	case "GET /series/1", "GET /movie/1":
		fmt.Fprintf(w, `{"id":1,"title":%q,"year":2020,"monitored":true}`, f.library[1])
	case "GET /series/lookup", "GET /movie/lookup":
		if q.Get("term") != "tvdb:555" && q.Get("term") != "show" && q.Get("term") != "tvdb:1" {
			io.WriteString(w, `[]`)
			return
		}
		io.WriteString(w, `[{"title":"New Show","year":2026,"tvdbId":555,"overview":"A show.","seasons":[{"seasonNumber":0},{"seasonNumber":1}],"images":[]},
			{"id":1,"title":"The Show","year":2020,"tvdbId":1}]`)
	case "GET /qualityprofile":
		io.WriteString(w, `[{"id":4,"name":"HD-1080p"},{"id":6,"name":"Ultra-HD"}]`)
	case "GET /rootfolder":
		io.WriteString(w, `[{"id":1,"path":"/tv","accessible":true,"freeSpace":100}]`)
	case "GET /languageprofile":
		w.WriteHeader(404)
	case "POST /series":
		json.Unmarshal(body, &f.added)
		f.library[42] = "New Show"
		io.WriteString(w, `{"id":42,"title":"New Show","year":2026,"tvdbId":555,"monitored":true}`)
	case "DELETE /series/42", "DELETE /series/1":
		f.deleted = r.URL.RequestURI()
		delete(f.library, 42)
	case "POST /command":
		io.WriteString(w, `{"id":99,"name":"SeriesSearch","status":"queued"}`)
	case "GET /history":
		io.WriteString(w, `{"totalRecords":1,"records":[{"eventType":"grabbed","date":"2026-11-03T10:00:00Z","sourceTitle":"Show.S01E02","quality":{"quality":{"name":"HDTV-1080p"}},"series":{"title":"The Show"},"episode":{"seasonNumber":1,"episodeNumber":2,"title":"Two"},"data":{"indexer":"NZBgeek","downloadUrl":"https://api.nzbgeek.info/?apikey=LEAKME"}}]}`)
	case "GET /indexer":
		io.WriteString(w, `[{"id":3,"name":"NZBgeek","enable":true,"protocol":"usenet","priority":25,"implementationName":"Newznab","fields":[{"name":"apiKey","value":"LEAKME"}]},{"id":4,"name":"Tracker","enable":true,"protocol":"torrent","fields":[]}]`)
	case "GET /indexer/3":
		io.WriteString(w, `{"id":3,"name":"NZBgeek","fields":[{"name":"apiKey","value":"LEAKME"}]}`)
	case "GET /indexerstatus":
		io.WriteString(w, `[{"indexerId":3,"disabledTill":"2026-11-04T13:00:00Z","mostRecentFailure":"2026-11-04T12:00:00Z"}]`)
	case "POST /indexer/test":
		w.WriteHeader(400)
		io.WriteString(w, `[{"propertyName":"ApiKey","errorMessage":"Invalid API key","severity":"error"}]`)
	case "POST /indexer/testall":
		w.WriteHeader(400)
		io.WriteString(w, `[{"id":3,"isValid":false,"validationFailures":[{"propertyName":"ApiKey","errorMessage":"Invalid API key"}]},{"id":4,"isValid":true,"validationFailures":[]}]`)
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, app, appName, api, key string) (*Module, *fakeArr) {
	f := &fakeArr{app: appName, api: api, library: map[int]string{1: "The Show", 2: "Another One"}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.now = func() time.Time { return time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC) }
	raw, _ := json.Marshal(Config{App: app, URL: srv.URL + "/sonarr/", APIKey: key})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://k": "key1", "secret://bad": "nope"}), "a", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "a", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestSonarr(t *testing.T) {
	m, f := setup(t, "sonarr", "Sonarr", "/api/v3", "secret://k")
	if h := m.Health(context.Background(), "a"); h.Status != "ok" || h.Message != "Sonarr 4.0.10 · 1 warnings" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"status", `{}`, `"Indexers unavailable due to failures: NZBgeek"`},
		{"queue", `{}`, `"progress":75`},
		{"queue", `{}`, `"part":"S01E02 Two"`},
		{"queue", `{}`, `"warnings":["Stalled"]`},
		{"calendar", `{}`, `"episode":"S01E05 Early"`},
		{"wanted", `{}`, `"episode":"S01E01 Pilot"`},
		{"library", `{"query":"show"}`, `"episodes":"3/10"`},
		{"lookup", `{"term":"show"}`, `"addWith":"555"`},
		{"history", `{}`, `"indexer":"NZBgeek"`},
		{"indexers", `{}`, `"failing":1`},
		{"test_indexers", `{}`, `"Invalid API key"`},
		{"test_indexers", `{"id":3}`, `"ok":false`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) || strings.Contains(string(r.Output), "LEAKME") {
			t.Fatalf("%s: %s %v", c.action, r.Output, err)
		}
	}
	r, _ := invoke(m, "calendar", `{}`, false)
	if strings.Index(string(r.Output), "Early") > strings.Index(string(r.Output), "Back") {
		t.Fatalf("calendar not sorted: %s", r.Output)
	}
	r, _ = invoke(m, "library", `{"query":"another"}`, false)
	if !strings.Contains(string(r.Output), `"matches":1`) || strings.Contains(string(r.Output), "The Show") {
		t.Fatal(string(r.Output))
	}

	// Add: already in the library, then a dry run, then for real and undo.
	if _, err := invoke(m, "add", `{"id":"1"}`, false); err == nil || !strings.Contains(err.Error(), "already in the library") {
		t.Fatal(err)
	}
	r, err := invoke(m, "add", `{"id":"555","qualityProfile":"ultra-hd"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Add series New Show (2026) to Sonarr" || !strings.Contains(string(r.Plan.Changes[0].After), `"qualityProfile":"Ultra-HD"`) || f.added != nil {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "add", `{"id":555,"search":false}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "remove" || string(r.Undo.Input) != `{"deleteFiles":false,"id":42}` {
		t.Fatalf("%+v %v", r, err)
	}
	if f.added["qualityProfileId"] != float64(4) || f.added["rootFolderPath"] != "/tv" || f.added["addOptions"].(map[string]any)["searchForMissingEpisodes"] != false {
		t.Fatalf("%+v", f.added)
	}
	if s := f.added["seasons"].([]any); s[0].(map[string]any)["monitored"] != false || s[1].(map[string]any)["monitored"] != true {
		t.Fatalf("seasons %+v", s)
	}
	if _, err := invoke(m, "add", `{"id":"555","qualityProfile":"nope"}`, false); err == nil || !strings.Contains(err.Error(), "HD-1080p") {
		t.Fatal(err)
	}
	f.library[42] = "New Show"
	// remove's plan reads item 1 in the fake; use it for the preview.
	if r, err := invoke(m, "remove", `{"id":1,"deleteFiles":true}`, true); err != nil || r.Plan == nil || !strings.Contains(r.Plan.Changes[0].Op, "delete its files") || f.deleted != "" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "remove", `{"id":1}`, false); err != nil || !strings.Contains(f.deleted, "deleteFiles=false") || !strings.Contains(f.deleted, "addImportListExclusion=false") {
		t.Fatalf("%v %s", err, f.deleted)
	}

	if r, err := invoke(m, "search", `{"id":1}`, true); err != nil || r.Plan == nil || r.Plan.Summary != "Search the indexers for The Show (2020)" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	n := len(f.seen)
	r, err = invoke(m, "search", `{"id":1}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"commandId":99`) || !strings.Contains(f.seen[n+1], `{"name":"SeriesSearch","seriesId":1}`) {
		t.Fatalf("%s %v %v", r.Output, err, f.seen[n:])
	}
	if _, err := invoke(m, "search", `{}`, false); err != nil || !strings.Contains(f.seen[len(f.seen)-1], `MissingEpisodeSearch`) {
		t.Fatal(err)
	}
}

func TestRadarrMissingFallback(t *testing.T) {
	m, _ := setup(t, "radarr", "Radarr", "/api/v3", "secret://k")
	r, err := invoke(m, "wanted", `{}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"total":2`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	// The instance says Sonarr, the server is Radarr.
	m2, _ := setup(t, "sonarr", "Radarr", "/api/v3", "secret://k")
	if h := m2.Health(context.Background(), "a"); h.Status != "degraded" || !strings.Contains(h.Message, "this server is Radarr") {
		t.Fatalf("%+v", h)
	}
}

func TestProwlarr(t *testing.T) {
	m, f := setup(t, "prowlarr", "Prowlarr", "/api/v1", "secret://k")
	if h := m.Health(context.Background(), "a"); h.Status != "ok" || !strings.HasPrefix(h.Message, "Prowlarr 4.0.10") {
		t.Fatalf("%+v", h)
	}
	if r, err := invoke(m, "indexers", `{}`, false); err != nil || !strings.Contains(string(r.Output), `"disabledTill"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	n := len(f.seen)
	for _, a := range []string{"queue", "calendar", "add", "remove", "search", "library"} {
		if _, err := invoke(m, a, `{"id":1}`, false); err == nil || !strings.Contains(err.Error(), "Prowlarr has no") {
			t.Fatalf("%s: %v", a, err)
		}
	}
	if len(f.seen) != n {
		t.Fatal("refused actions reached the server")
	}
}

func TestArrValidation(t *testing.T) {
	m, f := setup(t, "sonarr", "Sonarr", "/api/v3", "secret://k")
	for _, c := range []struct{ action, in string }{
		{"remove", `{}`},
		{"remove", `{"id":"1/../../system"}`},
		{"remove", `{"id":-1}`},
		{"remove", `{"id":1.5}`},
		{"search", `{"id":"x"}`},
		{"test_indexers", `{"id":"../x"}`},
		{"add", `{"id":"abc"}`},
		{"add", `{"id":"555","seriesType":"weird"}`},
		{"lookup", `{"term":" "}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{
		{App: "sonarr", URL: "http://nas:8989", APIKey: "plain"},
		{App: "sonarr", URL: "nas:8989", APIKey: "secret://k"},
		{App: "plex", URL: "http://nas:8989", APIKey: "secret://k"},
		{App: "sonarr", URL: "http://u:p@nas:8989", APIKey: "secret://k"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "sonarr", "Sonarr", "/api/v3", "secret://bad")
	if h := bad.Health(context.Background(), "a"); h.Status != "down" || h.Message != "Sonarr refused the API key" {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(bad, "queue", `{}`, false); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatal(err)
	}
}

func TestArrRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("X-Api-Key") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{App: "radarr", URL: srv.URL, APIKey: "secret://k"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://k": "key1"}), "a", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "a"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}

func TestManifest(t *testing.T) {
	risks := map[string]sdk.Risk{}
	for _, a := range New().Manifest().Actions {
		risks[a.Name] = a.Risk
		if a.Risk != sdk.RiskRead && !a.DryRun {
			t.Fatalf("%s changes state without a preview", a.Name)
		}
	}
	if risks["remove"] != sdk.RiskDestructive || risks["add"] != sdk.RiskWrite || risks["search"] != sdk.RiskWrite {
		t.Fatal(risks)
	}
}
