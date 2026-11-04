package onepassword

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

const (
	vaultID = "aaaaaaaaaaaaaaaaaaaaaaaaaa"
	itemID  = "bbbbbbbbbbbbbbbbbbbbbbbbbb"
	twinA   = "cccccccccccccccccccccccccc"
	twinB   = "dddddddddddddddddddddddddd"
)

type fake struct {
	mu   sync.Mutex
	seen []string
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/health" {
		io.WriteString(w, `{"name":"1Password Connect API","version":"1.7.3","dependencies":[{"service":"sync","status":"ACTIVE"},{"service":"sqlite","status":"ACTIVE","message":"Connected"}]}`)
		return
	}
	if r.Header.Get("Authorization") != "Bearer op-good" {
		w.WriteHeader(401)
		io.WriteString(w, `{"status":401,"message":"Invalid token signature"}`)
		return
	}
	f.mu.Lock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
	f.mu.Unlock()
	switch r.URL.Path {
	case "/v1/vaults":
		io.WriteString(w, `[{"id":"`+vaultID+`","name":"Infra","description":"servers","type":"USER_CREATED","items":3,"createdAt":"2025-01-01T00:00:00Z"}]`)
	case "/v1/vaults/" + vaultID + "/items":
		switch r.URL.Query().Get("filter") {
		case `title eq "DB"`:
			io.WriteString(w, `[{"id":"`+itemID+`","title":"DB","category":"DATABASE"}]`)
		case `title eq "Twin"`:
			io.WriteString(w, `[{"id":"`+twinA+`","title":"Twin"},{"id":"`+twinB+`","title":"Twin"}]`)
		case "":
			io.WriteString(w, `[{"id":"`+itemID+`","title":"DB","category":"DATABASE","tags":["prod"],"version":4,"urls":[{"href":"https://admin:pw@db.example.com/path?token=abc","primary":true},{"href":"panel.example.com/x"}]}]`)
		default:
			io.WriteString(w, `[]`)
		}
	case "/v1/vaults/" + vaultID + "/items/" + itemID:
		io.WriteString(w, `{"id":"`+itemID+`","title":"DB","category":"DATABASE","vault":{"id":"`+vaultID+`"},"version":4,
			"sections":[{"id":"s1","label":"Replica"}],
			"fields":[{"id":"username","label":"username","type":"STRING","purpose":"USERNAME","value":"app"},
				{"id":"password","label":"password","type":"CONCEALED","purpose":"PASSWORD","value":"hunter2"},
				{"id":"rpw00000000000000000000000","label":"token","type":"CONCEALED","section":{"id":"s1"},"value":"replica-pass"},
				{"id":"tok00000000000000000000000","label":"token","type":"CONCEALED","value":"main-tok"},
				{"id":"notesPlain","label":"notesPlain","type":"STRING","purpose":"NOTES","value":"root is s3cr3t-note"}],
			"files":[{"id":"f1","name":"ca.pem","size":1200,"content_path":"/v1/vaults/x/items/y/files/f1/content"}]}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"status":404,"message":"not found"}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fake) {
	f := &fake{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://op": "op-good", "secret://bad": "nope"}), "o", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "o", Action: action, Input: json.RawMessage(in)})
}

func noSecrets(t *testing.T, out string) {
	t.Helper()
	for _, s := range []string{"hunter2", "replica-pass", "main-tok", "s3cr3t-note", "op-good", "admin:pw", "token=abc", `"app"`} {
		if strings.Contains(out, s) {
			t.Fatalf("output leaks %s: %s", s, out)
		}
	}
}

func TestOnePasswordReads(t *testing.T) {
	m, _ := setup(t, "secret://op")
	if h := m.Health(context.Background(), "o"); h.Status != "ok" || !strings.Contains(h.Message, "1 vault") {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"health", `{}`, `"version":"1.7.3"`},
		{"vaults", `{}`, `"name":"Infra"`},
		{"items", `{"vault":"Infra"}`, `"urlHosts":["db.example.com","panel.example.com"]`},
		{"items", `{"vault":"infra","title":"DB"}`, `"count":1`},
		{"item", `{"vault":"` + vaultID + `","item":"DB"}`, `"label":"token","section":"Replica"`},
		{"item", `{"vault":"Infra","item":"` + itemID + `"}`, `"name":"ca.pem"`},
	} {
		r, err := invoke(m, c.action, c.in)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
		noSecrets(t, out)
	}
}

func TestOnePasswordReveal(t *testing.T) {
	m, f := setup(t, "secret://op")
	r, err := invoke(m, "reveal_field", `{"vault":"Infra","item":"DB","fields":["username","nope"]}`)
	if err != nil || !strings.Contains(string(r.Output), `"values":{"username":"app"}`) || !strings.Contains(string(r.Output), `"missing":["nope"]`) || strings.Contains(string(r.Output), "hunter2") {
		t.Fatalf("%s %v", r.Output, err)
	}
	// Two fields share a label: refused, with the ids to choose from.
	if _, err := invoke(m, "reveal_field", `{"vault":"Infra","item":"DB","fields":["token"]}`); err == nil || !strings.Contains(err.Error(), "rpw00000000000000000000000") {
		t.Fatal(err)
	}
	r, err = invoke(m, "reveal_field", `{"vault":"Infra","item":"DB","fields":["rpw00000000000000000000000"]}`)
	if err != nil || !strings.Contains(string(r.Output), "replica-pass") || strings.Contains(string(r.Output), "hunter2") || strings.Contains(string(r.Output), "main-tok") {
		t.Fatalf("%s %v", r.Output, err)
	}
	// Two items share a title.
	if _, err := invoke(m, "reveal_field", `{"vault":"Infra","item":"Twin","fields":["x"]}`); err == nil || !strings.Contains(err.Error(), twinB) {
		t.Fatal(err)
	}
	before := len(f.seen)
	for _, in := range []string{
		`{"vault":"Infra","item":"DB"}`,
		`{"vault":"Infra","item":"DB","fields":[]}`,
		`{"vault":"Infra","item":"DB","fields":["a","b","c","d","e","f","g","h","i","j","k"]}`,
		`{"vault":"Infra","item":"DB","fields":["bad\nlabel"]}`,
		`{"vault":"Infra","item":"x\" or title eq \"y","fields":["a"]}`,
		`{"vault":"","item":"DB","fields":["a"]}`,
	} {
		if _, err := invoke(m, "reveal_field", in); err == nil {
			t.Fatalf("accepted %s", in)
		}
	}
	if _, err := invoke(m, "items", `{"vault":"Infra","title":"a\"b"}`); err == nil {
		t.Fatal("accepted a quote in the filter")
	}
	if len(f.seen) != before {
		t.Fatalf("invalid input reached the server: %v", f.seen[before:])
	}
	for _, a := range m.Manifest().Actions {
		switch {
		case a.Name == "reveal_field":
			if a.Risk != sdk.RiskDestructive || !a.Sensitive {
				t.Fatal("reveal_field must be sensitive and destructive")
			}
		case a.Risk != sdk.RiskRead:
			t.Fatalf("%s must be a read", a.Name)
		}
	}
}

func TestOnePasswordConfigAndToken(t *testing.T) {
	for _, c := range []Config{{URL: "http://x:8080", Token: "plain"}, {URL: "ftp://x", Token: "secret://op"}, {URL: "http://u:p@x", Token: "secret://op"}, {URL: "http://x?a=b", Token: "secret://op"}, {URL: "https://x", Token: "secret://op", Fingerprint: "zz"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "o"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(bad, "vaults", `{}`); err == nil || !strings.Contains(err.Error(), "refused the token") || strings.Contains(err.Error(), "nope") {
		t.Fatal(err)
	}
}

func TestOnePasswordRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") + "!" }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://op"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://op": "op-good"}), "o", raw); err != nil {
		t.Fatal(err)
	}
	if _, err := invoke(m, "vaults", `{}`); err == nil || leaked != "" {
		t.Fatalf("followed the redirect: %v %q", err, leaked)
	}
}

// Only real host names leave the module: a URL field can hold a TOTP
// secret's otpauth:// link, a word or a password.
func TestOnePasswordHostsOnlyHostNames(t *testing.T) {
	got := hosts([]urlInfo{
		{Href: "https://db.example.com:5432/x?token=t"},
		{Href: "example.org/login"},
		{Href: "http://10.0.0.5/"},
		{Href: "https://münchen.de/"},
		{Href: "otpauth://totp/Issuer:alice?secret=JBSWY3DPEHPK3PXP"},
		{Href: "hunter2"},
		{Href: "https://intranet/"},
		{Href: "http://[::1]:8080/"},
		{Href: "https://a..b/"},
		{Href: "https://-x.example.com/"},
		{Href: "https://x_y.example.com/"},
		{Href: "my secret.value"},
	})
	if fmt.Sprint(got) != "[db.example.com example.org 10.0.0.5 münchen.de]" {
		t.Fatal(got)
	}
}
