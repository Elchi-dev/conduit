package umami

import (
	"context"
	"encoding/json"
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

const site = "0b6f5e8a-1c2d-4e3f-9a8b-7c6d5e4f3a21"

type fake struct {
	mu     sync.Mutex
	seen   []string
	logins int
	token  string
	v3     bool // answers in Umami 3's shapes
	prefix string
	cloud  bool
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, f.prefix)
	if path == "/auth/login" && r.Method == "POST" {
		var c map[string]string
		json.Unmarshal(body, &c)
		if c["username"] != "viewer" || c["password"] != "pw" {
			w.WriteHeader(401)
			io.WriteString(w, `{"error":"Incorrect username and/or password."}`)
			return
		}
		f.logins++
		f.token = "tok" + string(rune('0'+f.logins))
		io.WriteString(w, `{"token":"`+f.token+`","user":{"id":"u1","username":"viewer","role":"view-only"}}`)
		return
	}
	if f.cloud {
		if r.Header.Get("x-umami-api-key") != "cloudkey" {
			w.WriteHeader(401)
			io.WriteString(w, `{"error":"Unauthorized"}`)
			return
		}
	} else if r.Header.Get("Authorization") != "Bearer "+f.token || f.token == "" {
		w.WriteHeader(401)
		io.WriteString(w, `Unauthorized`)
		return
	}
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
	q := r.URL.Query()
	switch r.Method + " " + path {
	case "GET /websites":
		io.WriteString(w, `{"data":[{"id":"`+site+`","name":"Blog","domain":"blog.example.com","shareId":"SHARE-SECRET","createdAt":"2025-01-01T00:00:00Z"}],"count":1,"page":1,"pageSize":100}`)
	case "GET /websites/" + site + "/stats":
		if q.Get("startAt") == "" || q.Get("endAt") == "" {
			w.WriteHeader(400)
			return
		}
		if f.v3 {
			io.WriteString(w, `{"pageviews":900,"visitors":300,"visits":400,"bounces":100,"totaltime":48000,"comparison":{}}`)
		} else {
			io.WriteString(w, `{"pageviews":{"value":900,"prev":800},"visitors":{"value":300,"prev":1},"visits":{"value":400,"prev":1},"bounces":{"value":100,"prev":1},"totaltime":{"value":48000,"prev":1}}`)
		}
	case "GET /websites/" + site + "/active":
		if f.v3 {
			io.WriteString(w, `{"visitors":4}`)
		} else {
			io.WriteString(w, `{"x":3}`)
		}
	case "GET /websites/" + site + "/metrics":
		if f.v3 && q.Get("type") == "url" {
			w.WriteHeader(400)
			io.WriteString(w, `{"error":"Invalid type"}`)
			return
		}
		switch q.Get("type") {
		case "url", "path":
			io.WriteString(w, `[{"x":"/","y":500},{"x":"/about","y":120}]`)
		case "referrer":
			io.WriteString(w, `[{"x":null,"y":50},{"x":"news.ycombinator.com","y":40}]`)
		default:
			io.WriteString(w, `[{"x":"DE","y":70}]`)
		}
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"error":"Not found"}`)
	}
}

var now = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

func setup(t *testing.T, f *fake, cfg Config) *Module {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	m.Now = func() time.Time { return now }
	if f.cloud {
		m.Base = srv.URL
	} else {
		f.prefix = "/umami/api"
		cfg.Address = srv.URL + "/umami"
	}
	raw, _ := json.Marshal(cfg)
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://pw": "pw", "secret://ck": "cloudkey", "secret://bad": "nope"}), "u", raw); err != nil {
		t.Fatal(err)
	}
	return m
}

func invoke(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "u", Action: action, Input: json.RawMessage(in)})
}

func TestUmamiSelfHosted(t *testing.T) {
	for _, v3 := range []bool{false, true} {
		f := &fake{v3: v3}
		m := setup(t, f, Config{Username: "viewer", Password: "secret://pw"})
		if h := m.Health(context.Background(), "u"); h.Status != "ok" || h.Message != "signed in as viewer" {
			t.Fatalf("%+v", h)
		}
		active := `"visitors":3`
		if v3 {
			active = `"visitors":4`
		}
		for _, c := range []struct{ action, in, want string }{
			{"websites", `{}`, `"domain":"blog.example.com"`},
			{"stats", `{"website":"` + site + `","period":"30d"}`, `"bounceRate":25`},
			{"stats", `{"website":"` + strings.ToUpper(site) + `"}`, `"avgVisitSeconds":120`},
			{"active", `{"website":"` + site + `"}`, active},
			{"top", `{"website":"` + site + `","by":"page","limit":5}`, `{"count":120,"page":"/about"}`},
			{"top", `{"website":"` + site + `","by":"referrer"}`, `{"count":50,"referrer":"(none)"}`},
			{"top", `{"website":"` + site + `","by":"country","from":"2026-10-01","to":"2026-10-31"}`, `"period":"2026-10-01 to 2026-10-31"`},
		} {
			r, err := invoke(m, c.action, c.in)
			if err != nil || !strings.Contains(string(r.Output), c.want) || strings.Contains(string(r.Output), "SHARE-SECRET") || strings.Contains(string(r.Output), "tok") {
				t.Fatalf("v3=%v %s %s: %s %v", v3, c.action, c.in, r.Output, err)
			}
		}
		if f.logins != 1 {
			t.Fatalf("signed in %d times", f.logins)
		}
		// A custom range ends at the end of "to", in milliseconds.
		last := f.seen[len(f.seen)-1]
		if !strings.Contains(last, "startAt=1790812800000") || !strings.Contains(last, "endAt=1793491199999") {
			t.Fatal(last)
		}
	}
}

func TestUmamiRenewsSession(t *testing.T) {
	f := &fake{}
	m := setup(t, f, Config{Username: "viewer", Password: "secret://pw"})
	if _, err := invoke(m, "websites", `{}`); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.token = "rotated"
	f.mu.Unlock()
	if _, err := invoke(m, "websites", `{}`); err != nil || f.logins != 2 {
		t.Fatalf("%v logins=%d", err, f.logins)
	}
}

func TestUmamiCloud(t *testing.T) {
	f := &fake{cloud: true, v3: true}
	m := setup(t, f, Config{APIKey: "secret://ck"})
	if h := m.Health(context.Background(), "u"); h.Status != "ok" || h.Message != "Umami Cloud" {
		t.Fatalf("%+v", h)
	}
	r, err := invoke(m, "stats", `{"website":"`+site+`","period":"24h"}`)
	if err != nil || !strings.Contains(string(r.Output), `"pageviews":900`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	if !strings.Contains(f.seen[1], "startAt=1793707200000") {
		t.Fatal(f.seen[1])
	}
	bad := setup(t, &fake{cloud: true}, Config{APIKey: "secret://bad"})
	if h := bad.Health(context.Background(), "u"); h.Status != "down" || !strings.Contains(h.Message, "refused the API key") {
		t.Fatalf("%+v", h)
	}
}

func TestUmamiValidation(t *testing.T) {
	f := &fake{}
	m := setup(t, f, Config{Username: "viewer", Password: "secret://pw"})
	for _, c := range []struct{ action, in string }{
		{"stats", `{"website":"../users"}`},
		{"stats", `{"website":"` + site + `/../x"}`},
		{"stats", `{}`},
		{"stats", `{"website":"` + site + `","period":"5y"}`},
		{"stats", `{"website":"` + site + `","from":"2026-10-01"}`},
		{"stats", `{"website":"` + site + `","from":"2026-10-05","to":"2026-10-01"}`},
		{"stats", `{"website":"` + site + `","from":"2027-01-01","to":"2027-01-02"}`},
		{"active", `{"website":"abc"}`},
		{"top", `{"website":"` + site + `","by":"session"}`},
		{"top", `{"website":"` + site + `","by":"page","limit":101}`},
	} {
		if _, err := invoke(m, c.action, c.in); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 || f.logins != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{
		{Address: "https://umami.example.com", Username: "viewer", Password: "plain"},
		{Address: "https://umami.example.com", Password: "secret://pw"},
		{Username: "viewer", Password: "secret://pw"},
		{Address: "javascript:alert(1)", Username: "viewer", Password: "secret://pw"},
		{Address: "https://u:p@umami.example.com", Username: "viewer", Password: "secret://pw"},
		{APIKey: "plainkey"},
		{APIKey: "secret://ck", Username: "viewer"},
		{APIKey: "secret://ck", Address: "https://umami.example.com"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad := setup(t, &fake{}, Config{Username: "viewer", Password: "secret://bad"})
	if h := bad.Health(context.Background(), "u"); h.Status != "down" || h.Message != "Umami refused the user name or password" {
		t.Fatalf("%+v", h)
	}
	for _, a := range m.Manifest().Actions {
		if a.Risk != sdk.RiskRead {
			t.Fatalf("%s isn't read-only", a.Name)
		}
	}
}

func TestUmamiRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	for _, cfg := range []Config{{Address: srv.URL, Username: "viewer", Password: "secret://pw"}, {APIKey: "secret://ck"}} {
		m := New()
		m.HTTP = srv.Client()
		m.Base = srv.URL
		raw, _ := json.Marshal(cfg)
		if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://pw": "pw", "secret://ck": "cloudkey"}), "u", raw); err != nil {
			t.Fatal(err)
		}
		if h := m.Health(context.Background(), "u"); h.Status != "down" || hit {
			t.Fatalf("followed the redirect: %+v", h)
		}
	}
}
