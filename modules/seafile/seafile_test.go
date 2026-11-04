package seafile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

const repo = "6f1d2a3b-0000-4000-8000-123456789abc"

type fakeSeafile struct {
	mu    sync.Mutex
	seen  []string
	links map[string]string // token -> path
	n     int
	// editable links let people edit; old makes POST answer with the
	// item's existing link, as Seafile before multiple links per item did.
	editable map[string]bool
	old      bool
}

func (f *fakeSeafile) link(tok, path string) string {
	return fmt.Sprintf(`{"username":"alice@example.com","repo_id":%q,"repo_name":"Docs","path":%q,"obj_name":"report.pdf","is_dir":false,"token":%q,
		"link":"https://sf.example.com/f/%s/","view_cnt":2,"ctime":"2026-11-01T00:00:00+00:00","expire_date":"","is_expired":false,"password":"LEAKME-PW",
		"permissions":{"can_edit":%t,"can_download":true,"can_upload":false}}`, repo, path, tok, tok, f.editable[tok])
}

func (f *fakeSeafile) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Token good-token-123" {
		w.WriteHeader(401)
		io.WriteString(w, `{"detail":"Invalid token"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	q := r.URL.Query()
	switch {
	case r.Method == "GET" && r.URL.Path == "/seafile/api2/account/info/":
		io.WriteString(w, `{"email":"alice@example.com","usage":1073741824,"total":10737418240}`)
	case r.Method == "GET" && r.URL.Path == "/seafile/api2/repos/":
		fmt.Fprintf(w, `[{"id":%q,"name":"Docs","type":"repo","owner":"LEAKME@example.com","size":2048,"mtime":1700000000,"encrypted":false,"permission":"rw"}]`, repo)
	case r.Method == "GET" && r.URL.Path == "/seafile/api2/repos/"+repo+"/dir/":
		if q.Get("p") != "/Docs" {
			w.WriteHeader(404)
			io.WriteString(w, `{"error_msg":"Folder not found."}`)
			return
		}
		io.WriteString(w, `[{"id":"x","type":"dir","name":"Old","mtime":1700000000},{"id":"y","type":"file","name":"report.pdf","size":2048,"mtime":1700000000,"modifier_email":"LEAKME"}]`)
	case r.Method == "GET" && r.URL.Path == "/seafile/api2/repos/"+repo+"/file/detail/":
		io.WriteString(w, `{"id":"abc","type":"file","name":"report.pdf","size":2048,"mtime":1700000000,"last_modifier_email":"LEAKME"}`)
	case r.Method == "GET" && r.URL.Path == "/seafile/api/v2.1/share-links/":
		var parts []string
		for tok, path := range f.links {
			if q.Get("path") == "" || q.Get("path") == path {
				parts = append(parts, f.link(tok, path))
			}
		}
		io.WriteString(w, "["+strings.Join(parts, ",")+"]")
	case r.Method == "POST" && r.URL.Path == "/seafile/api/v2.1/share-links/":
		var b map[string]any
		json.Unmarshal(body, &b)
		if f.old {
			for tok, path := range f.links {
				if path == b["path"] {
					io.WriteString(w, f.link(tok, path))
					return
				}
			}
		}
		f.n++
		tok := fmt.Sprintf("tok%017d", f.n)
		f.links[tok] = b["path"].(string)
		io.WriteString(w, f.link(tok, f.links[tok]))
	case r.Method == "DELETE" && strings.HasPrefix(r.URL.Path, "/seafile/api/v2.1/share-links/"):
		tok := strings.Trim(strings.TrimPrefix(r.URL.Path, "/seafile/api/v2.1/share-links/"), "/")
		delete(f.links, tok)
		io.WriteString(w, `{"success":true}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"error_msg":"not found"}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fakeSeafile) {
	f := &fakeSeafile{links: map[string]string{}, editable: map[string]bool{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/seafile/", Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://sf": "good-token-123", "secret://bad": "nope"}), "s", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "s", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestSeafile(t *testing.T) {
	m, f := setup(t, "secret://sf")
	if h := m.Health(context.Background(), "s"); h.Status != "ok" || h.Message != "1.0 GB of 10.0 GB used" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"libraries", `{}`, `"kind":"mine"`},
		{"list_dir", `{"repo":"` + repo + `","path":"/Docs/"}`, `"name":"report.pdf"`},
		{"file_info", `{"repo":"` + repo + `","path":"/Docs/report.pdf"}`, `"size":2048`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}
	in := `{"repo":"` + repo + `","path":"/Docs/report.pdf"}`
	r, err := invoke(m, "create_share_link", in, true)
	if err != nil || r.Plan == nil || len(f.links) != 0 || !strings.Contains(r.Plan.Summary, "anyone") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "create_share_link", in, false)
	if err != nil || len(f.links) != 1 || r.Undo == nil || r.Undo.Action != "revoke_share_link" || strings.Contains(string(r.Output), "LEAKME") {
		t.Fatalf("%+v %v", r, err)
	}
	// The undo carries the link's id, never its token.
	if strings.Contains(string(r.Undo.Input), "tok") || !strings.Contains(string(r.Output), "/f/tok") {
		t.Fatalf("%s %s", r.Undo.Input, r.Output)
	}
	if r2, err := invoke(m, "create_share_link", in, false); err != nil || !strings.Contains(string(r2.Output), "nothing to change") || len(f.links) != 1 {
		t.Fatalf("existing: %s %v", r2.Output, err)
	}
	if r2, err := invoke(m, "share_links", `{}`, false); err != nil || strings.Contains(string(r2.Output), "LEAKME") || !strings.Contains(string(r2.Output), string(r.Undo.Input[7:30])) {
		t.Fatalf("links: %s %v", r2.Output, err)
	}
	if p, err := invoke(m, r.Undo.Action, string(r.Undo.Input), true); err != nil || p.Plan == nil || len(f.links) != 1 {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || len(f.links) != 0 {
		t.Fatal(err, f.links)
	}
	if r2, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || !strings.Contains(string(r2.Output), "nothing to change") {
		t.Fatalf("%s %v", r2.Output, err)
	}
	for _, a := range m.Manifest().Actions {
		if strings.Contains(a.Name, "share_link") && a.Name != "share_links" && a.Risk != sdk.RiskDestructive {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestSeafileValidation(t *testing.T) {
	m, f := setup(t, "secret://sf")
	for _, c := range []struct{ action, in string }{
		{"list_dir", `{}`},
		{"list_dir", `{"repo":"../x"}`},
		{"list_dir", `{"repo":"` + repo + `","path":"/a/../b"}`},
		{"list_dir", `{"repo":"` + repo + `","path":"relative"}`},
		{"file_info", `{"repo":"` + repo + `"}`},
		{"file_info", `{"repo":"` + repo + `","path":"/a\nb"}`},
		{"create_share_link", `{"repo":"` + repo + `","path":"/"}`},
		{"create_share_link", `{"repo":"` + repo + `","path":"/x","expireDays":-1}`},
		{"revoke_share_link", `{"id":"tok00000000000000001"}`},
		{"share_links", `{"repo":"nope"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{URL: "https://sf.example.com", Token: "plain"}, {URL: "sf.example.com", Token: "secret://sf"},
		{URL: "https://u:p@sf.example.com", Token: "secret://sf"}, {URL: "https://sf.example.com/?x=1", Token: "secret://sf"}, {URL: "https://sf.example.com/#x", Token: "secret://sf"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "s"); h.Status != "down" || h.Message != "Seafile refused the API token" {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(bad, "libraries", `{}`, false); err == nil || strings.Contains(err.Error(), "nope") {
		t.Fatal(err)
	}
}

func TestSeafileRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://sf"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://sf": "good-token-123"}), "s", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "s"); h.Status != "down" || leaked != "" || strings.Contains(h.Message, "good-token") {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}

func TestSeafileShareLinkReuseAndUndo(t *testing.T) {
	m, f := setup(t, "secret://sf")
	in := `{"repo":"` + repo + `","path":"/Docs/report.pdf"}`
	// An existing link that lets people edit isn't handed out as a
	// view-and-download link.
	f.links["tok00000000000000099"] = "/Docs/report.pdf"
	f.editable["tok00000000000000099"] = true
	r, err := invoke(m, "create_share_link", in, false)
	if err != nil || strings.Contains(string(r.Output), "tok00000000000000099") || r.Undo == nil || len(f.links) != 2 {
		t.Fatalf("%s %+v %v", r.Output, r.Undo, err)
	}
	// An older server answers a POST with the existing link: no undo, since
	// it would revoke a link that was there before.
	m2, f2 := setup(t, "secret://sf")
	f2.old = true
	f2.links["tok00000000000000077"] = "/Docs/report.pdf"
	r, err = invoke(m2, "create_share_link", `{"repo":"`+repo+`","path":"/Docs/report.pdf","password":"long-password"}`, false)
	if err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "weren't applied") || len(f2.links) != 1 {
		t.Fatalf("%s %+v %v", r.Output, r.Undo, err)
	}
	// Ids are keyed with the API token: a plain hash of the link's token
	// isn't one.
	plain := sha256.Sum256([]byte("seafile-share:tok00000000000000077"))
	if strings.Contains(string(r.Output), hex.EncodeToString(plain[:12])) || !strings.Contains(string(r.Output), `"id":"l`) {
		t.Fatalf("%s", r.Output)
	}
}
