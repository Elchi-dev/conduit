package dropbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

const (
	appKey    = "abcdef123456"
	appSecret = "APP-SECRET-LEAKME"
	refresh   = "REFRESH-TOKEN-LEAKME"
)

type fakeDropbox struct {
	mu       sync.Mutex
	api      []string
	tokens   int
	valid    map[string]bool
	links    map[string]string // file id -> url
	redirect string
}

func (f *fakeDropbox) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	if r.URL.Path == "/oauth2/token" {
		u, p, _ := r.BasicAuth()
		form, _ := url.ParseQuery(string(body))
		if u != appKey || p != appSecret || form.Get("refresh_token") != refresh {
			w.WriteHeader(400)
			fmt.Fprintf(w, `{"error":"invalid_grant","error_description":"refresh token is malformed: %s"}`, p)
			return
		}
		f.tokens++
		tok := fmt.Sprintf("sl.ACCESS-%d", f.tokens)
		f.valid[tok] = true
		fmt.Fprintf(w, `{"access_token":%q,"token_type":"bearer","expires_in":14400}`, tok)
		return
	}
	if !f.valid[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")] {
		w.WriteHeader(401)
		io.WriteString(w, `{"error_summary":"expired_access_token/","error":{".tag":"expired_access_token"}}`)
		return
	}
	f.api = append(f.api, r.URL.Path+" "+string(body))
	if f.redirect != "" {
		http.Redirect(w, r, f.redirect, http.StatusFound)
		return
	}
	var a map[string]any
	json.Unmarshal(body, &a)
	conflict := func(s string) {
		w.WriteHeader(409)
		fmt.Fprintf(w, `{"error_summary":%q,"error":{".tag":"x"}}`, s)
	}
	file := `{".tag":"file","name":"report.pdf","path_display":"/Docs/report.pdf","id":"id:abc123","size":2048,"server_modified":"2026-11-01T00:00:00Z","content_hash":"h"}`
	switch r.URL.Path {
	case "/2/users/get_space_usage":
		if len(body) != 0 || r.Header.Get("Content-Type") != "" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"used":1073741824,"allocation":{".tag":"individual","allocated":2147483648}}`)
	case "/2/files/list_folder":
		fmt.Fprintf(w, `{"entries":[%s,{".tag":"folder","name":"Old","path_display":"/Docs/Old","id":"id:def456"}],"cursor":"LEAKME","has_more":true}`, file)
	case "/2/files/search_v2":
		fmt.Fprintf(w, `{"matches":[{"metadata":{".tag":"metadata","metadata":%s}}]}`, file)
	case "/2/files/get_metadata":
		if a["path"] == "/Docs/report.pdf" || a["path"] == "id:abc123" {
			io.WriteString(w, file)
		} else {
			conflict("path/not_found/..")
		}
	case "/2/sharing/list_shared_links":
		if u := f.links["id:abc123"]; u != "" && (a["path"] == "/Docs/report.pdf" || a["path"] == "id:abc123") {
			fmt.Fprintf(w, `{"links":[{".tag":"file","url":%q,"name":"report.pdf","id":"id:abc123"}]}`, u)
		} else {
			io.WriteString(w, `{"links":[]}`)
		}
	case "/2/sharing/create_shared_link_with_settings":
		f.links["id:abc123"] = "https://www.dropbox.com/scl/fi/xyz/report.pdf?rlkey=SHARED&dl=0"
		fmt.Fprintf(w, `{".tag":"file","url":%q,"name":"report.pdf","id":"id:abc123","link_permissions":{"resolved_visibility":{".tag":"team_only"},"effective_audience":{".tag":"team"},"link_access_level":{".tag":"viewer"}}}`, f.links["id:abc123"])
	case "/2/sharing/revoke_shared_link":
		if a["url"] != f.links["id:abc123"] {
			conflict("shared_link_not_found/")
			return
		}
		delete(f.links, "id:abc123")
		io.WriteString(w, `null`)
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, secretRef string) (*Module, *fakeDropbox) {
	t.Helper()
	f := &fakeDropbox{valid: map[string]bool{}, links: map[string]string{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base, m.TokenURL = srv.URL, srv.URL+"/oauth2/token"
	raw, _ := json.Marshal(Config{AppKey: appKey, AppSecret: secretRef, RefreshToken: "secret://rt"})
	h := fakehost.New(map[string]string{"secret://as": appSecret, "secret://rt": refresh, "secret://bad": "WRONG-SECRET"})
	if err := m.Configure(context.Background(), h, "d", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action string, in any, dry bool) (sdk.Result, error) {
	b, _ := json.Marshal(in)
	return m.Invoke(context.Background(), sdk.Call{Instance: "d", Action: action, Input: b, DryRun: dry})
}

func noLeak(t *testing.T, s string) {
	t.Helper()
	for _, bad := range []string{appSecret, refresh, "sl.ACCESS", "LEAKME", "WRONG-SECRET"} {
		if strings.Contains(s, bad) {
			t.Fatalf("leak %q: %s", bad, s)
		}
	}
}

func TestSettingsRefused(t *testing.T) {
	for _, c := range []Config{
		{},
		{AppKey: appKey, AppSecret: "plain", RefreshToken: "secret://rt"},
		{AppKey: appKey, AppSecret: "secret://as", RefreshToken: "plain"},
		{AppKey: "bad key!", AppSecret: "secret://as", RefreshToken: "secret://rt"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Errorf("accepted %+v", c)
		}
	}
}

func TestReadsAndRefresh(t *testing.T) {
	m, f := setup(t, "secret://as")
	if h := m.Health(context.Background(), "d"); h.Status != "ok" || h.Message != "1.0 GB of 2.0 GB used" {
		t.Fatalf("%+v", h)
	}
	r, err := invoke(m, "list_folder", map[string]any{"path": "/Docs/", "limit": 1}, false)
	if err != nil {
		t.Fatal(err)
	}
	noLeak(t, string(r.Output))
	if !strings.Contains(string(r.Output), "report.pdf") || strings.Contains(string(r.Output), "Old") || !strings.Contains(string(r.Output), `"more":true`) {
		t.Fatal(string(r.Output))
	}
	if !strings.Contains(f.api[1], `"path":"/Docs"`) {
		t.Fatal(f.api[1])
	}
	if _, err := invoke(m, "search", map[string]any{"query": "report"}, false); err != nil {
		t.Fatal(err)
	}
	if f.tokens != 1 {
		t.Fatalf("token not cached: %d", f.tokens)
	}
	f.mu.Lock()
	f.valid = map[string]bool{}
	f.mu.Unlock()
	r, err = invoke(m, "metadata", map[string]any{"path": "id:abc123"}, false)
	if err != nil || !strings.Contains(string(r.Output), `"contentHash":"h"`) {
		t.Fatalf("%v %s", err, r.Output)
	}
	if f.tokens != 2 {
		t.Fatalf("no refresh after 401: %d", f.tokens)
	}
	c, _ := m.set.Get("d")
	c.tok.Now = func() time.Time { return time.Now().Add(5 * time.Hour) }
	if _, err := invoke(m, "metadata", map[string]any{"path": "/Docs/report.pdf"}, false); err != nil {
		t.Fatal(err)
	}
	if f.tokens != 3 {
		t.Fatalf("expired token kept: %d", f.tokens)
	}
	if _, err := invoke(m, "metadata", map[string]any{"path": "/nope"}, false); err == nil || err.Error() != "there's nothing at that path in Dropbox" {
		t.Fatal(err)
	}
}

func TestBadCredentials(t *testing.T) {
	m, f := setup(t, "secret://bad")
	h := m.Health(context.Background(), "d")
	if h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
	noLeak(t, h.Message)
	if len(f.api) != 0 {
		t.Fatal(f.api)
	}
}

func TestSharedLinkAndUndo(t *testing.T) {
	m, f := setup(t, "secret://as")
	r, err := invoke(m, "create_shared_link", map[string]any{"path": "/Docs/report.pdf"}, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "/Docs/report.pdf") || !strings.Contains(string(r.Plan.Changes[0].After), "team's policy") || len(f.links) != 0 {
		t.Fatalf("%v %+v", err, r.Plan)
	}
	r, err = invoke(m, "create_shared_link", map[string]any{"path": "/Docs/report.pdf"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if r.Undo == nil || r.Undo.Action != "revoke_shared_link" || string(r.Undo.Input) != `{"id":"id:abc123"}` {
		t.Fatalf("%+v", r.Undo)
	}
	// The result names the audience Dropbox gave the link (a team's policy).
	if !strings.Contains(string(r.Output), `"audience":"team"`) || !strings.Contains(string(r.Output), `"access":"viewer"`) {
		t.Fatal(string(r.Output))
	}
	// Again: nothing to change, and no undo for a link it didn't make.
	r, err = invoke(m, "create_shared_link", map[string]any{"path": "/Docs/report.pdf"}, false)
	if err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%v %s %+v", err, r.Output, r.Undo)
	}
	p, err := invoke(m, "revoke_shared_link", map[string]any{"id": "id:abc123"}, true)
	if err != nil || !strings.Contains(p.Plan.Summary, "Revoke 1 shared link") || len(f.links) != 1 {
		t.Fatalf("%v %+v", err, p.Plan)
	}
	r, err = invoke(m, "revoke_shared_link", map[string]any{"id": "id:abc123"}, false)
	if err != nil || !strings.Contains(string(r.Output), `"revoked":1`) || len(f.links) != 0 {
		t.Fatalf("%v %s", err, r.Output)
	}
	r, err = invoke(m, "revoke_shared_link", map[string]any{"id": "id:abc123"}, false)
	if err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%v %s", err, r.Output)
	}
	r, err = invoke(m, "revoke_shared_link", map[string]any{"url": "https://www.dropbox.com/scl/fi/gone"}, false)
	if err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%v %s", err, r.Output)
	}
}

func TestInvalidInputNeverReachesDropbox(t *testing.T) {
	m, f := setup(t, "secret://as")
	for _, c := range []struct {
		action string
		in     map[string]any
	}{
		{"list_folder", map[string]any{"path": "Docs"}},
		{"list_folder", map[string]any{"path": "/a/../b"}},
		{"list_folder", map[string]any{"path": "/a\nb"}},
		{"metadata", map[string]any{"path": ""}},
		{"search", map[string]any{"query": ""}},
		{"search", map[string]any{"query": "a\nb"}},
		{"create_shared_link", map[string]any{"path": "/a", "expires": "tomorrow"}},
		{"create_shared_link", map[string]any{"path": "/a", "expires": "2001-01-01T00:00:00Z"}},
		{"revoke_shared_link", map[string]any{}},
		{"revoke_shared_link", map[string]any{"url": "https://evil.example/x"}},
		{"revoke_shared_link", map[string]any{"url": "http://www.dropbox.com/x"}},
		{"revoke_shared_link", map[string]any{"id": "abc"}},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Errorf("%s %v accepted", c.action, c.in)
		}
	}
	if len(f.api) != 0 || f.tokens != 0 {
		t.Fatal(f.api, f.tokens)
	}
}

func TestCrossHostRedirectRefused(t *testing.T) {
	hits := 0
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer other.Close()
	m, f := setup(t, "secret://as")
	f.redirect = other.URL
	if _, err := invoke(m, "search", map[string]any{"query": "x"}, false); !errors.Is(err, rest.ErrCrossHostRedirect) {
		t.Fatal(err)
	}
	if hits != 0 {
		t.Fatal("followed")
	}
}
