package sourcegraph

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

// The planted credentials sit in matched code lines; none may come back.
var leaks = []string{"AKIAPLANTEDLEAKEDKEY1234", "ghp_plantedLeakedTokenValue000", "hunter2planted"}

type fakeSG struct {
	mu   sync.Mutex
	seen []map[string]any
}

func (s *fakeSG) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "token sg-good" {
		w.WriteHeader(401)
		io.WriteString(w, `Invalid access token.`)
		return
	}
	if r.URL.Path != "/.api/graphql" || r.Method != "POST" {
		w.WriteHeader(404)
		return
	}
	var b struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}
	json.NewDecoder(r.Body).Decode(&b)
	s.mu.Lock()
	s.seen = append(s.seen, map[string]any{"query": b.Query, "variables": b.Variables})
	s.mu.Unlock()
	switch {
	case strings.Contains(b.Query, "currentUser"):
		io.WriteString(w, `{"data":{"currentUser":{"username":"alice"}}}`)
	case strings.Contains(b.Query, "repositories("):
		io.WriteString(w, `{"data":{"repositories":{"nodes":[{"name":"github.com/acme/api","description":"API","url":"/github.com/acme/api"}]}}}`)
	case strings.Contains(b.Query, "search("):
		q, _ := b.Variables["query"].(string)
		if strings.HasPrefix(q, "type:repo") {
			io.WriteString(w, `{"data":{"search":{"results":{"matchCount":1,"limitHit":false,"results":[{"__typename":"Repository","name":"github.com/acme/api","url":"/github.com/acme/api"}]}}}}`)
			return
		}
		if strings.Contains(q, "broken") {
			io.WriteString(w, `{"data":null,"errors":[{"message":"invalid query near token=ghp_plantedLeakedTokenValue000"}]}`)
			return
		}
		lines := []string{}
		for i := 0; i < 15; i++ {
			lines = append(lines, fmt.Sprintf(`{"preview":"aws_key = \"AKIAPLANTEDLEAKEDKEY1234\" password=hunter2planted %s","lineNumber":%d}`, strings.Repeat("x", 400), i))
		}
		file := `{"__typename":"FileMatch","repository":{"name":"github.com/acme/api"},"file":{"path":"config/prod.py"},"lineMatches":[` + strings.Join(lines, ",") + `]}`
		io.WriteString(w, `{"data":{"search":{"results":{"matchCount":15,"limitHit":true,"results":[`+file+`,{"__typename":"CommitSearchResult"}]}}}}`)
	default:
		w.WriteHeader(400)
	}
}

func setup(t *testing.T, tok string) (*Module, *fakeSG) {
	s := &fakeSG{}
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/.api/graphql", Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://sg": "sg-good", "secret://bad": "sg-bad"}), "s", raw); err != nil {
		t.Fatal(err)
	}
	return m, s
}

func invoke(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "s", Action: action, Input: json.RawMessage(in)})
}

func TestSourcegraph(t *testing.T) {
	m, s := setup(t, "secret://sg")
	if h := m.Health(context.Background(), "s"); h.Status != "ok" || h.Message != "signed in as alice" {
		t.Fatalf("%+v", h)
	}
	r, err := invoke(m, "search", `{"query":"lang:python aws_key","limit":5}`)
	if err != nil {
		t.Fatal(err)
	}
	out := string(r.Output)
	for _, l := range append(leaks, "sg-good") {
		if strings.Contains(out, l) {
			t.Fatalf("leaked %q: %s", l, out)
		}
	}
	var res struct {
		Files []struct {
			Path    string `json:"path"`
			Matches []struct {
				Line int    `json:"line"`
				Text string `json:"text"`
			} `json:"matches"`
		} `json:"files"`
		Truncated bool `json:"truncated"`
		Other     int  `json:"otherResults"`
	}
	json.Unmarshal(r.Output, &res)
	if len(res.Files) != 1 || len(res.Files[0].Matches) != 5 || !res.Truncated || res.Other != 1 || res.Files[0].Matches[0].Line != 1 || res.Files[0].Path != "config/prod.py" {
		t.Fatalf("%s", out)
	}
	for _, x := range res.Files[0].Matches {
		if n := len([]rune(x.Text)); n > maxLine+1 {
			t.Fatalf("line of %d characters", n)
		}
	}
	last := s.seen[len(s.seen)-1]
	if last["variables"].(map[string]any)["query"] != "lang:python aws_key count:5" || strings.Contains(last["query"].(string), "aws_key") {
		t.Fatalf("the query must travel as a variable: %v", last)
	}
	for _, m := range m.Manifest().Actions {
		if m.Name == "search" && (!m.Sensitive || m.Reversible) {
			t.Fatal("search must be sensitive")
		}
	}
	// GraphQL errors come back redacted.
	if _, err := invoke(m, "search", `{"query":"broken"}`); err == nil || strings.Contains(err.Error(), "ghp_planted") || !strings.Contains(err.Error(), "[redacted]") {
		t.Fatal(err)
	}
	for _, c := range []struct{ in, want, query string }{
		{`{}`, `"name":"github.com/acme/api"`, ""},
		{`{"name":"acme/api"}`, `"url":"/github.com/acme/api"`, `type:repo repo:acme/api count:50`},
		{`{"name":"a.b"}`, `"repositories"`, `type:repo repo:a\.b count:50`},
	} {
		r, err := invoke(m, "repositories", c.in)
		if err != nil || !strings.Contains(string(r.Output), c.want) {
			t.Fatalf("%s %v", r.Output, err)
		}
		v := s.seen[len(s.seen)-1]["variables"].(map[string]any)
		if c.query != "" && v["query"] != c.query {
			t.Fatalf("%v", v)
		}
	}
}

func TestSourcegraphValidation(t *testing.T) {
	m, s := setup(t, "secret://sg")
	for _, c := range []struct{ action, in string }{
		{"search", `{}`}, {"search", `{"query":"  "}`}, {"search", `{"query":"x count:all"}`}, {"search", `{"query":"COUNT:5 x"}`},
		{"search", `{"query":"a\nb"}`}, {"search", `{"query":"x","limit":101}`}, {"search", `{"query":"` + strings.Repeat("a", 1001) + `"}`},
		{"repositories", `{"name":"x\" OR y"}`}, {"repositories", `{"limit":500}`}, {"repositories", `{"name":"a b"}`},
	} {
		if _, err := invoke(m, c.action, c.in); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(s.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", s.seen)
	}
	for _, c := range []Config{{URL: "https://sg.example.com", Token: "plain"}, {URL: "sg.example.com", Token: "secret://sg"}, {URL: "https://a:b@sg.example.com", Token: "secret://sg"},
		{URL: "https://sg.example.com/#x", Token: "secret://sg"}, {URL: "https://sg.example.com?x=1", Token: "secret://sg"}, {URL: "ftp://sg.example.com", Token: "secret://sg"},
		{URL: "https://sg.example.com", Token: "secret://sg", Fingerprint: "nope"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "s"); h.Status != "down" || h.Message != "Sourcegraph refused the access token" {
		t.Fatalf("%+v", h)
	}
}

func TestSourcegraphRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://sg"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://sg": "sg-good"}), "s", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "s"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
