package gitguardian

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

// leaks are planted in the fake answers wherever GitGuardian puts the
// secret or something derived from it; none may reach the output.
var leaks = []string{"AKIAPLANTEDLEAKVALUE", "ghp_plantedLeakedSecretValue", "plantedhashvalue", "share.gitguardian.com", "dev@example.com", "Jane Leaker"}

type fakeGG struct {
	mu      sync.Mutex
	seen    []string
	status  map[int64]string
	reason  map[int64]string
	revoked map[int64]bool
	// dropBody makes resolve and ignore keep revoked false and the reason empty.
	dropBody bool
}

func (g *fakeGG) incident(id int64, occ bool) string {
	o := "null"
	if occ {
		o = `[{"id":1,"incident_id":` + fmt.Sprint(id) + `,"kind":"historical","sha":"d670460b4b4aece5915caf5c68d12f560a9fe3e4","source":{"id":6,"type":"github","full_name":"acme/api","url":"https://github.com/acme/api"},
			"author_name":"Jane Leaker","author_info":"dev@example.com","date":"2026-10-01T10:00:00Z","presence":"present","url":"https://github.com/acme/api/commit/d670460#ghp_plantedLeakedSecretValue",
			"matches":[{"name":"apikey","match":"AKIAPLANTEDLEAKVALUE","indice_start":1,"indice_end":20}],"filepath":"config/prod.env"}]`
	}
	return fmt.Sprintf(`{"id":%d,"date":"2026-10-01T10:00:00Z","detector":{"name":"aws_iam","display_name":"AWS Keys","family":"apikey"},"secret_hash":"plantedhashvalue","hmsl_hash":"plantedhashvalue",
		"gitguardian_url":"https://dashboard.gitguardian.com/workspace/1/incidents/%d","share_url":"https://share.gitguardian.com/AKIAPLANTEDLEAKVALUE","status":%q,"ignore_reason":%q,"secret_revoked":%t,
		"severity":"critical","validity":"valid","occurrences_count":3,"assignee_email":"dev@example.com","tags":["PUBLIC"],"occurrences":%s}`,
		id, id, g.status[id], g.reason[id], g.revoked[id], o)
}

func (g *fakeGG) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Token gg-good" {
		w.WriteHeader(401)
		io.WriteString(w, `{"detail":"Invalid API key."}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	g.mu.Lock()
	defer g.mu.Unlock()
	g.seen = append(g.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	var b map[string]any
	json.Unmarshal(body, &b)
	var id int64
	fmt.Sscanf(strings.TrimPrefix(r.URL.Path, "/v1/incidents/secrets/"), "%d", &id)
	switch {
	case r.URL.Path == "/v1/health":
		io.WriteString(w, `{"detail":"Valid API key."}`)
	case r.URL.Path == "/v1/incidents/secrets":
		w.Header().Set("Link", `<https://api.gitguardian.com/v1/incidents/secrets?cursor=abc>; rel="next"`)
		io.WriteString(w, "["+g.incident(7, false)+"]")
	case g.status[id] == "":
		w.WriteHeader(404)
		io.WriteString(w, `{"detail":"Not found."}`)
	case r.Method == "GET":
		if r.URL.Query().Get("with_occurrences") != "" {
			io.WriteString(w, g.incident(id, true))
			return
		}
		io.WriteString(w, g.incident(id, false))
	case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/resolve"):
		g.status[id] = "RESOLVED"
		g.revoked[id], _ = b["secret_revoked"].(bool)
		if g.dropBody {
			g.revoked[id] = false
		}
		io.WriteString(w, g.incident(id, false))
	case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/ignore"):
		g.status[id] = "IGNORED"
		g.reason[id], _ = b["ignore_reason"].(string)
		if g.dropBody {
			g.reason[id] = ""
		}
		io.WriteString(w, g.incident(id, false))
	case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/reopen"):
		g.status[id], g.reason[id], g.revoked[id] = "TRIGGERED", "", false
		io.WriteString(w, g.incident(id, false))
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, tok string) (*Module, *fakeGG) {
	g := &fakeGG{status: map[int64]string{7: "TRIGGERED"}, reason: map[int64]string{}, revoked: map[int64]bool{}}
	srv := httptest.NewServer(g)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://gg": "gg-good", "secret://bad": "gg-bad"}), "g", raw); err != nil {
		t.Fatal(err)
	}
	return m, g
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "g", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func noLeak(t *testing.T, what string, r sdk.Result) {
	t.Helper()
	all, _ := json.Marshal(r)
	for _, l := range append(leaks, "gg-good") {
		if strings.Contains(string(all), l) {
			t.Fatalf("%s leaked %q: %s", what, l, all)
		}
	}
}

func TestGitGuardian(t *testing.T) {
	m, g := setup(t, "secret://gg")
	if h := m.Health(context.Background(), "g"); h.Status != "ok" || h.Message != "over 1 untriaged incidents" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"incidents", `{}`, `"truncated":true`},
		{"incidents", `{"status":"TRIGGERED","severity":"critical"}`, `"type":"AWS Keys"`},
		{"incident", `{"incident":7}`, `"commit":"d670460"`},
		{"incident", `{"incident":7}`, `"file":"config/prod.env"`},
		{"incident", `{"incident":7}`, `"repository":"acme/api"`},
		{"incident", `{"incident":7}`, `"dashboard":"https://dashboard.gitguardian.com/workspace/1/incidents/7"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) {
			t.Fatalf("%s: %s %v", c.action, r.Output, err)
		}
		noLeak(t, c.action, r)
	}
	if !strings.Contains(g.seen[len(g.seen)-1], "with_occurrences=") {
		t.Fatal(g.seen)
	}
	// Resolve: preview changes nothing, then resolve, nothing to change, undo reopens.
	r, err := invoke(m, "resolve_incident", `{"incident":7,"revoked":true}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Resolve incident 7" || g.status[7] != "TRIGGERED" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	noLeak(t, "preview", r)
	r, err = invoke(m, "resolve_incident", `{"incident":7,"revoked":true}`, false)
	if err != nil || g.status[7] != "RESOLVED" || !g.revoked[7] || r.Undo == nil || r.Undo.Action != "reopen_incident" {
		t.Fatalf("%+v %v", r, err)
	}
	noLeak(t, "resolve", r)
	if r, err := invoke(m, "resolve_incident", `{"incident":7,"revoked":true}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "ignore_incident", `{"incident":7,"reason":"low_risk"}`, false); err == nil || !strings.Contains(err.Error(), "reopen it first") {
		t.Fatal(err)
	}
	r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false)
	if err != nil || g.status[7] != "TRIGGERED" || r.Undo == nil || string(r.Undo.Input) != `{"incident":7,"revoked":true}` {
		t.Fatalf("%+v %v", r, err)
	}
	// Ignore and undo; reopening an ignored incident ignores it again with its reason.
	r, err = invoke(m, "ignore_incident", `{"incident":7,"reason":"test_credential"}`, false)
	if err != nil || g.status[7] != "IGNORED" || g.reason[7] != "test_credential" || r.Undo == nil || r.Undo.Action != "reopen_incident" {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = invoke(m, "reopen_incident", `{"incident":7}`, false)
	if err != nil || g.status[7] != "TRIGGERED" || r.Undo == nil || string(r.Undo.Input) != `{"incident":7,"reason":"test_credential"}` {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "reopen_incident", `{"incident":7}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "incident", `{"incident":99}`, false); err == nil || !strings.Contains(err.Error(), "no incident") {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if (a.Name == "resolve_incident" || a.Name == "ignore_incident") && (a.Risk != sdk.RiskDestructive || !a.DryRun || !a.Reversible) {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

// A resolve that loses the revoked flag, or an ignore that loses its reason,
// is reported, not taken as done: undo would otherwise set back a state
// GitGuardian never had.
func TestGitGuardianChecksTheChange(t *testing.T) {
	m, g := setup(t, "secret://gg")
	g.dropBody = true
	if _, err := invoke(m, "resolve_incident", `{"incident":7,"revoked":true}`, false); err == nil || !strings.Contains(err.Error(), "didn't apply") {
		t.Fatal(err)
	}
	g.status[7] = "TRIGGERED"
	if _, err := invoke(m, "ignore_incident", `{"incident":7,"reason":"low_risk"}`, false); err == nil || !strings.Contains(err.Error(), "didn't apply") {
		t.Fatal(err)
	}
}

func TestDashboardLink(t *testing.T) {
	for s, want := range map[string]bool{
		"https://dashboard.gitguardian.com/workspace/1/incidents/7":     true,
		"https://dashboard.eu1.gitguardian.com/workspace/1/incidents/7": true,
		"https://evilgitguardian.com/workspace/1/incidents/7":           false,
		"https://dashboard.gitguardian.com.evil.io/x":                   false,
		"http://dashboard.gitguardian.com/workspace/1/incidents/7":      false,
		"https://share.gitguardian.com/AKIA":                            false,
		"https://dashboard.gitguardian.com/share/incidents/abc":         false,
		"https://u:p@dashboard.gitguardian.com/workspace/1":             false,
	} {
		u, _ := url.Parse(s)
		if dashboardLink(u) != want {
			t.Errorf("%s: want %t", s, want)
		}
	}
}

func TestGitGuardianValidation(t *testing.T) {
	m, g := setup(t, "secret://gg")
	g.seen = nil
	for _, c := range []struct{ action, in string }{
		{"incident", `{}`}, {"incident", `{"incident":-1}`}, {"incident", `{"incident":"7/../1"}`},
		{"resolve_incident", `{"incident":7}`}, {"ignore_incident", `{"incident":7}`}, {"ignore_incident", `{"incident":7,"reason":"meh"}`},
		{"incidents", `{"status":"OPEN"}`}, {"incidents", `{"severity":"severe"}`}, {"incidents", `{"limit":500}`}, {"reopen_incident", `{"incident":0}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(g.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", g.seen)
	}
	for _, c := range []Config{{Token: "plain-key"}, {Token: "secret://gg", Region: "mars"}, {Token: ""}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "g"); h.Status != "down" || h.Message != "GitGuardian refused the API key" {
		t.Fatalf("%+v", h)
	}
}

func TestGitGuardianRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Token: "secret://gg"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://gg": "gg-good"}), "g", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "g"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
