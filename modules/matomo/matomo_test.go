package matomo

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

const token = "0123456789abcdef0123456789abcdef"

type fake struct {
	mu       sync.Mutex
	seen     []url.Values
	urls     []string
	redirect string
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.urls = append(f.urls, r.Method+" "+r.URL.RequestURI())
	if f.redirect != "" {
		http.Redirect(w, r, f.redirect, http.StatusTemporaryRedirect)
		return
	}
	body, _ := io.ReadAll(r.Body)
	form, _ := url.ParseQuery(string(body))
	f.seen = append(f.seen, form)
	if r.Method != "POST" || r.URL.Path != "/analytics/index.php" || r.URL.RawQuery != "" || form.Get("module") != "API" || form.Get("format") != "JSON" {
		w.WriteHeader(404)
		return
	}
	if form.Get("token_auth") != token {
		// Matomo answers 200 with an error, and may echo what it got.
		io.WriteString(w, `{"result":"error","message":"Unable to authenticate with the provided token `+form.Get("token_auth")+`. It is either invalid or expired."}`)
		return
	}
	switch form.Get("method") {
	case "API.getMatomoVersion":
		io.WriteString(w, `{"value":"5.1.2"}`)
	case "SitesManager.getSitesWithAtLeastViewAccess":
		io.WriteString(w, `[{"idsite":"1","name":"Shop","main_url":"https://shop.example.com","timezone":"Europe/Berlin","currency":"EUR","ecommerce":"1"},{"idsite":2,"name":"Blog","main_url":"https://blog.example.com","ecommerce":0}]`)
	case "VisitsSummary.get":
		if form.Get("idSite") == "9" {
			io.WriteString(w, `{"result":"error","message":"You can't access this resource as it requires 'view' access for the website id = 9."}`)
			return
		}
		if form.Get("date") == "2020-01-01" {
			io.WriteString(w, `[]`)
			return
		}
		io.WriteString(w, `{"nb_uniq_visitors":80,"nb_users":3,"nb_visits":100,"nb_actions":250,"bounce_count":40,"sum_visit_length":9000,"bounce_rate":"40%","nb_actions_per_visit":2.5,"avg_time_on_site":90,"nb_visits_converted":2}`)
	case "Actions.getPageUrls":
		io.WriteString(w, `[{"label":"/","nb_visits":60,"nb_hits":80,"avg_time_on_page":30,"bounce_rate":"35%","exit_rate":"50%"},{"label":"/pricing","nb_visits":20,"nb_hits":22},{"label":"/x","nb_visits":1}]`)
	case "Referrers.getAll":
		io.WriteString(w, `[{"label":"Google","referer_type":2,"nb_visits":30},{"label":"news.example.org","referer_type":3,"nb_visits":5}]`)
	case "Live.getCounters":
		io.WriteString(w, `[{"visits":"4","actions":"9","visitors":"3","visitsConverted":"0"}]`)
	default:
		io.WriteString(w, `{"result":"error","message":"The method doesn't exist"}`)
	}
}

func setup(t *testing.T, ref string) (*Module, *fake) {
	t.Helper()
	f := &fake{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(Config{Address: srv.URL + "/analytics/", Token: ref})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://mt": token, "secret://bad": "badtoken-LEAKME-1234567"}), "m", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "m", Action: action, Input: json.RawMessage(in)})
}

func TestMatomoReads(t *testing.T) {
	m, f := setup(t, "secret://mt")
	if h := m.Health(context.Background(), "m"); h.Status != "ok" || !strings.Contains(h.Message, "5.1.2") {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"sites", `{}`, `"ecommerce":true,"name":"Shop","site":1`},
		{"visits_summary", `{"site":1}`, `"bounceRate":40`},
		{"visits_summary", `{"site":1,"period":"day","date":"yesterday"}`, `"visitors":80`},
		{"visits_summary", `{"site":1,"date":"2020-01-01"}`, `"visits":0`},
		{"visits_summary", `{"site":1,"from":"2026-01-01","to":"2026-12-31"}`, `"period":"range"`},
		{"top_pages", `{"site":1,"limit":2}`, `{"avgTimeOnPageSeconds":0,"bounceRate":0,"exitRate":0,"page":"/pricing","pageviews":22,"visits":20}`},
		{"top_referrers", `{"site":1}`, `{"referrer":"Google","type":"search","visits":30}`},
		{"live", `{"site":1}`, `"visitors":3`},
	} {
		r, err := invoke(m, c.action, c.in)
		if err != nil || !strings.Contains(string(r.Output), c.want) {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
	}
	last := f.seen[len(f.seen)-1]
	if last.Get("method") != "Live.getCounters" || last.Get("lastMinutes") != "30" || last.Get("idSite") != "1" {
		t.Fatal(last)
	}
	r, _ := invoke(m, "top_pages", `{"site":1,"limit":2}`)
	if strings.Contains(string(r.Output), `"/x"`) || !strings.Contains(string(r.Output), `"truncated":true`) {
		t.Fatal(string(r.Output))
	}
	if last := f.seen[len(f.seen)-1]; last.Get("filter_limit") != "2" || last.Get("flat") != "1" || last.Get("period") != "month" || last.Get("date") != "today" {
		t.Fatal(last)
	}
	if _, err := invoke(m, "visits_summary", `{"site":9}`); err == nil || !strings.Contains(err.Error(), "view access") {
		t.Fatal(err)
	}
	// The token travels only in POST bodies.
	for _, u := range f.urls {
		if strings.Contains(u, token) || strings.Contains(u, "token_auth") || !strings.HasPrefix(u, "POST ") {
			t.Fatal(u)
		}
	}
	for _, a := range m.Manifest().Actions {
		if a.Risk != sdk.RiskRead {
			t.Fatalf("%s isn't read-only", a.Name)
		}
	}
}

func TestMatomoBadToken(t *testing.T) {
	m, _ := setup(t, "secret://bad")
	h := m.Health(context.Background(), "m")
	if h.Status != "down" || !strings.Contains(h.Message, "refused the auth token") || strings.Contains(h.Message, "LEAKME") {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(m, "sites", `{}`); err == nil || strings.Contains(err.Error(), "LEAKME") {
		t.Fatal(err)
	}
	// An error that quotes the token in another shape is scrubbed too.
	if got := clean("bad request for badtoken-LEAKME-1234567 here", "badtoken-LEAKME-1234567"); strings.Contains(got, "LEAKME") {
		t.Fatal(got)
	}
	if got := clean(strings.Repeat("x ", 400)+token, ""); strings.Contains(got, token) || len([]rune(got)) > 301 {
		t.Fatal(got)
	}
}

func TestMatomoValidation(t *testing.T) {
	m, f := setup(t, "secret://mt")
	for _, c := range []struct{ action, in string }{
		{"visits_summary", `{}`},
		{"visits_summary", `{"site":0}`},
		{"visits_summary", `{"site":"1;DROP"}`},
		{"visits_summary", `{"site":1,"period":"range"}`},
		{"visits_summary", `{"site":1,"date":"last7"}`},
		{"visits_summary", `{"site":1,"date":"2026-13-01"}`},
		{"visits_summary", `{"site":1,"from":"2025-01-01","to":"2026-01-02"}`},
		{"visits_summary", `{"site":1,"from":"2026-02-01","to":"2026-01-01"}`},
		{"visits_summary", `{"site":1,"from":"2026-01-01"}`},
		{"visits_summary", `{"site":1,"period":"day","from":"2026-01-01","to":"2026-01-02"}`},
		{"visits_summary", `{"site":1,"limit":5}`},
		{"top_pages", `{"site":1,"limit":1001}`},
		{"top_referrers", `{"site":1,"limit":-2}`},
		{"live", `{"site":1,"minutes":5000}`},
		{"live", `{"site":1,"period":"day"}`},
		{"visitor_log", `{"site":1}`},
	} {
		if _, err := invoke(m, c.action, c.in); err == nil {
			t.Errorf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.urls) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.urls)
	}
	for _, c := range []Config{
		{Token: "secret://mt"},
		{Address: "https://matomo.example.com", Token: token},
		{Address: "ftp://matomo.example.com", Token: "secret://mt"},
		{Address: "https://u:p@matomo.example.com", Token: "secret://mt"},
		{Address: "https://matomo.example.com/?token_auth=x", Token: "secret://mt"},
		{Address: "https://matomo.example.com/a/../b", Token: "secret://mt"},
		{Address: "https://matomo.example.com", Token: "secret://mt", Fingerprint: "nothex"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Errorf("accepted %+v", c)
		}
	}
}

func TestMatomoRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	m, f := setup(t, "secret://mt")
	f.redirect = evil.URL + "/index.php"
	if _, err := invoke(m, "sites", `{}`); !errors.Is(err, rest.ErrCrossHostRedirect) || hit {
		t.Fatalf("followed the redirect: %v", err)
	}
}
