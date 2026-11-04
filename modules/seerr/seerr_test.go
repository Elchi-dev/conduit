package seerr

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

type fakeSeerr struct {
	mu       sync.Mutex
	writes   []string
	reads    []string
	status   map[int]int // request id → status
	nextID   int
	searches []string
}

func reqJSON(id, status int, kind string, tmdb int) string {
	seasons := `[]`
	if kind == "tv" {
		seasons = `[{"seasonNumber":1,"status":2},{"seasonNumber":2,"status":2}]`
	}
	return fmt.Sprintf(`{"id":%d,"status":%d,"type":"%s","is4k":false,"createdAt":"2026-11-0%dT10:00:00.000Z","updatedAt":"2026-11-04T11:00:00.000Z",
		"media":{"tmdbId":%d,"status":2,"status4k":1,"mediaType":"%s"},"seasons":%s,
		"requestedBy":{"id":2,"displayName":"Carol","email":"carol@example.com","plexUsername":"carolp"},"modifiedBy":{"id":1,"displayName":"Admin","email":"admin@example.com"}}`,
		id, status, kind, id%9+1, tmdb, kind, seasons)
}

func (f *fakeSeerr) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api/v1/status" {
		io.WriteString(w, `{"version":"1.33.2","commitTag":"v1.33.2","updateAvailable":true,"commitsBehind":0}`)
		return
	}
	if r.Header.Get("X-Api-Key") != "key" {
		w.WriteHeader(403)
		io.WriteString(w, `{"message":"You do not have permission to access this endpoint"}`)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	if r.Method != "GET" {
		f.writes = append(f.writes, r.Method+" "+r.URL.Path+" "+string(body))
	} else {
		f.reads = append(f.reads, r.URL.Path+"?"+r.URL.RawQuery)
	}
	switch p := r.URL.Path; {
	case r.Method == "GET" && p == "/api/v1/request/count":
		io.WriteString(w, `{"total":10,"movie":6,"tv":4,"pending":2,"approved":5,"declined":1,"processing":1,"available":1}`)
	case r.Method == "GET" && p == "/api/v1/request":
		q := r.URL.Query()
		if q.Get("filter") != "pending" || q.Get("take") != "20" || q.Get("sort") != "added" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"pageInfo":{"pages":1,"pageSize":20,"results":2,"page":1},"results":[`+reqJSON(7, f.status[7], "movie", 603)+`,`+reqJSON(8, f.status[8], "tv", 1399)+`]}`)
	case r.Method == "GET" && p == "/api/v1/movie/603":
		io.WriteString(w, `{"id":603,"title":"The Matrix","releaseDate":"1999-03-30","mediaInfo":{"status":2}}`)
	case r.Method == "GET" && p == "/api/v1/tv/1399":
		io.WriteString(w, `{"id":1399,"name":"Game of Thrones","firstAirDate":"2011-04-17"}`)
	case r.Method == "GET" && p == "/api/v1/movie/550":
		io.WriteString(w, `{"id":550,"title":"Fight Club","releaseDate":"1999-10-15"}`)
	case r.Method == "GET" && p == "/api/v1/search":
		f.searches = append(f.searches, r.URL.RawQuery)
		if strings.Contains(r.URL.RawQuery, "+") || strings.Contains(r.URL.RawQuery, "&x=") {
			w.WriteHeader(400)
			io.WriteString(w, `{"message":"request/query/query must be url encoded"}`)
			return
		}
		io.WriteString(w, `{"page":1,"totalPages":1,"totalResults":3,"results":[{"id":603,"mediaType":"movie","title":"The Matrix","releaseDate":"1999-03-30","overview":"`+strings.Repeat("a", 400)+`","mediaInfo":{"status":5}},
			{"id":1399,"mediaType":"tv","name":"Game of Thrones","firstAirDate":"2011-04-17"},{"id":6384,"mediaType":"person","name":"Keanu Reeves"}]}`)
	case r.Method == "POST" && p == "/api/v1/request":
		var b map[string]any
		json.Unmarshal(body, &b)
		if b["mediaId"] == float64(603) {
			w.WriteHeader(409)
			io.WriteString(w, `{"message":"Request for this media already exists."}`)
			return
		}
		f.nextID++
		f.status[f.nextID] = 2
		w.WriteHeader(201)
		io.WriteString(w, reqJSON(f.nextID, 2, b["mediaType"].(string), int(b["mediaId"].(float64))))
	default:
		var id int
		var verb string
		if n, _ := fmt.Sscanf(p, "/api/v1/request/%d/%s", &id, &verb); n == 2 && r.Method == "POST" {
			if _, ok := f.status[id]; !ok {
				w.WriteHeader(404)
				return
			}
			f.status[id] = map[string]int{"approve": 2, "decline": 3}[verb]
			io.WriteString(w, reqJSON(id, f.status[id], "movie", 603))
			return
		}
		if n, _ := fmt.Sscanf(p, "/api/v1/request/%d", &id); n == 1 && strings.Count(p, "/") == 4 {
			st, ok := f.status[id]
			if !ok {
				w.WriteHeader(404)
				io.WriteString(w, `{"message":"Request not found."}`)
				return
			}
			kind, tmdb := "movie", 603
			if id == 8 {
				kind, tmdb = "tv", 1399
			}
			if id > 100 {
				tmdb = 550
			}
			switch r.Method {
			case "GET":
				io.WriteString(w, reqJSON(id, st, kind, tmdb))
			case "DELETE":
				delete(f.status, id)
				w.WriteHeader(204)
			}
			return
		}
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"Not Found"}`)
	}
}

func setup(t *testing.T, key string) (*Module, *fakeSeerr) {
	f := &fakeSeerr{status: map[int]int{7: 1, 8: 1, 9: 2}, nextID: 100}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/api/v1/", APIKey: key})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://k": "key", "secret://bad": "nope"}), "o", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "o", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestSeerrRead(t *testing.T) {
	m, f := setup(t, "secret://k")
	if h := m.Health(context.Background(), "o"); h.Status != "ok" || h.Message != "version 1.33.2 · 2 pending request(s) · update available" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"requests", `{}`, `{"id":7,"mediaStatus":"pending","requestedAt":"2026-11-08T10:00:00.000Z","requestedBy":"Carol","status":"pending","title":"The Matrix","tmdbId":603,"type":"movie","year":"1999"}`},
		{"requests", `{}`, `"seasons":[1,2]`},
		{"requests", `{}`, `"counts":{"total":10,"movie":6,"tv":4,"pending":2,"approved":5,"declined":1,"processing":1,"available":1}`},
		{"request", `{"id":9}`, `"modifiedAt":"2026-11-04T11:00:00.000Z","modifiedBy":"Admin","requestedAt":"2026-11-01T10:00:00.000Z","requestedBy":"Carol","status":"approved","title":"The Matrix"`},
		{"search", `{"query":"the matrix: reloaded & co"}`, `{"mediaType":"movie","overview":"` + strings.Repeat("a", 300) + `…","status":"available","title":"The Matrix","tmdbId":603,"year":"1999"}`},
		{"search", `{"query":"the matrix"}`, `{"mediaType":"tv","status":"not requested","title":"Game of Thrones","tmdbId":1399,"year":"2011"}`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) || strings.Contains(string(r.Output), "@example.com") || strings.Contains(string(r.Output), "Keanu") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
	}
	if f.searches[0] != "query=the%20matrix%3A%20reloaded%20%26%20co&page=1" {
		t.Fatal(f.searches)
	}
	for _, a := range m.Manifest().Actions {
		if (a.Name == "requests" || a.Name == "request") != a.Sensitive {
			t.Fatal(a.Name, "sensitive")
		}
		risk := map[string]sdk.Risk{"approve": sdk.RiskDestructive, "decline": sdk.RiskWrite, "create_request": sdk.RiskWrite, "delete_request": sdk.RiskDestructive}[a.Name]
		if risk == "" {
			risk = sdk.RiskRead
		}
		if a.Risk != risk || (a.Name == "create_request") != a.Reversible || (risk != sdk.RiskRead) != a.DryRun {
			t.Fatal(a.Name, a.Risk)
		}
	}
}

func TestSeerrWrites(t *testing.T) {
	m, f := setup(t, "secret://k")
	p, err := invoke(m, "approve", `{"id":7}`, true)
	if err != nil || p.Plan == nil || p.Plan.Summary != "Approve request 7 for The Matrix (1999)" || len(f.writes) != 0 {
		t.Fatalf("%+v %v", p, err)
	}
	r, err := invoke(m, "approve", `{"id":7}`, false)
	if err != nil || r.Undo != nil || f.status[7] != 2 || string(r.Output) != `{"id":7,"request":"request 7 for The Matrix (1999)","status":"approved"}` || f.writes[0] != "POST /api/v1/request/7/approve " {
		t.Fatalf("%s %v %v", r.Output, err, f.writes)
	}
	if _, err := invoke(m, "decline", `{"id":7}`, false); err == nil || !strings.Contains(err.Error(), "isn't pending; it's approved") || len(f.writes) != 1 {
		t.Fatal(err)
	}
	if r, err := invoke(m, "decline", `{"id":8}`, false); err != nil || r.Undo != nil || f.status[8] != 3 || !strings.Contains(string(r.Output), `"status":"declined"`) || !strings.Contains(string(r.Output), "Game of Thrones (2011)") {
		t.Fatalf("%s %v", r.Output, err)
	}

	p, err = invoke(m, "create_request", `{"mediaType":"tv","tmdbId":1399,"seasons":[1,3]}`, true)
	if err != nil || p.Plan.Summary != "Request Game of Thrones (2011), seasons 1, 3" || string(p.Plan.Changes[0].After) != `{"is4k":false,"mediaId":1399,"mediaType":"tv","seasons":[1,3]}` || len(f.writes) != 2 {
		t.Fatalf("%+v %v", p.Plan, err)
	}
	r, err = invoke(m, "create_request", `{"mediaType":"movie","tmdbId":550,"is4k":true}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "delete_request" || string(r.Undo.Input) != `{"id":101}` ||
		f.writes[2] != `POST /api/v1/request {"is4k":true,"mediaId":550,"mediaType":"movie"}` || !strings.Contains(string(r.Output), `"request":"Fight Club (1999) in 4K"`) {
		t.Fatalf("%s %+v %v %v", r.Output, r.Undo, err, f.writes)
	}
	if p, err := invoke(m, r.Undo.Action, string(r.Undo.Input), true); err != nil || p.Plan.Summary != "Delete request 101 for Fight Club (1999)" {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.status[101] != 0 || f.writes[3] != "DELETE /api/v1/request/101 " {
		t.Fatal(err, f.writes)
	}
	if _, err := invoke(m, "create_request", `{"mediaType":"tv","tmdbId":1399}`, false); err != nil || f.writes[4] != `POST /api/v1/request {"is4k":false,"mediaId":1399,"mediaType":"tv","seasons":"all"}` {
		t.Fatal(err, f.writes)
	}
	if _, err := invoke(m, "create_request", `{"mediaType":"movie","tmdbId":603}`, false); err == nil || err.Error() != "The Matrix (1999) is already requested" {
		t.Fatal(err)
	}
	if _, err := invoke(m, "request", `{"id":55}`, false); err == nil || err.Error() != "there's no such request" {
		t.Fatal(err)
	}
}

func TestSeerrRefusals(t *testing.T) {
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "o"); h.Status != "down" || h.Message != "Overseerr refused the API key" {
		t.Fatalf("%+v", h)
	}
	m, f := setup(t, "secret://k")
	for _, c := range []struct{ action, in string }{
		{"approve", `{}`},
		{"approve", `{"id":0}`},
		{"approve", `{"id":-3}`},
		{"approve", `{"id":"7/decline"}`},
		{"decline", `{"id":99999999999}`},
		{"delete_request", `{"id":"../settings"}`},
		{"request", `{}`},
		{"requests", `{"filter":"declined&take=1000"}`},
		{"requests", `{"limit":101}`},
		{"search", `{"query":""}`},
		{"search", `{"query":"a\nb"}`},
		{"search", `{"query":"` + strings.Repeat("x", 201) + `"}`},
		{"search", `{"query":"x","page":21}`},
		{"create_request", `{"mediaType":"person","tmdbId":1}`},
		{"create_request", `{"mediaType":"movie"}`},
		{"create_request", `{"mediaType":"movie","tmdbId":0}`},
		{"create_request", `{"mediaType":"movie","tmdbId":550,"seasons":[1]}`},
		{"create_request", `{"mediaType":"tv","tmdbId":1399,"seasons":"some"}`},
		{"create_request", `{"mediaType":"tv","tmdbId":1399,"seasons":[]}`},
		{"create_request", `{"mediaType":"tv","tmdbId":1399,"seasons":[1,1]}`},
		{"create_request", `{"mediaType":"tv","tmdbId":1399,"seasons":[-1]}`},
		{"create_request", `{"mediaType":"tv","tmdbId":1399,"seasons":{"a":1}}`},
		{"delete_media", `{"id":1}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.writes) != 0 || len(f.reads) != 0 {
		t.Fatalf("refused input reached the server: %v %v", f.writes, f.reads)
	}
	for _, c := range []Config{{URL: "http://o:5055", APIKey: "plainkey"}, {URL: "o:5055", APIKey: "secret://k"}, {URL: "http://u:p@o:5055", APIKey: "secret://k"}, {URL: "http://o:5055/#x", APIKey: "secret://k"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("X-Api-Key") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	rm := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, APIKey: "secret://k"})
	rm.Configure(context.Background(), fakehost.New(map[string]string{"secret://k": "key"}), "o", raw)
	if h := rm.Health(context.Background(), "o"); h.Status != "down" || !strings.Contains(h.Message, "another host") || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
