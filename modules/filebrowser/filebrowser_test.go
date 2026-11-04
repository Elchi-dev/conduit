package filebrowser

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

const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoxfQ.c2lnbmF0dXJl"

type fakeFB struct {
	mu     sync.Mutex
	seen   []string
	logins int
	shares map[string]string // hash -> path
	n      int
}

func (f *fakeFB) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path == "/fb/api/login" {
		var b map[string]string
		json.Unmarshal(body, &b)
		if b["username"] != "alice" || b["password"] != "pw-LEAKME" {
			w.WriteHeader(403)
			io.WriteString(w, "403 Forbidden")
			return
		}
		f.logins++
		io.WriteString(w, jwt)
		return
	}
	if r.Header.Get("X-Auth") != jwt {
		w.WriteHeader(401)
		return
	}
	f.seen = append(f.seen, r.Method+" "+r.URL.EscapedPath()+"?"+r.URL.RawQuery+" "+string(body))
	switch {
	case r.Method == "GET" && r.URL.Path == "/fb/api/usage/":
		io.WriteString(w, `{"total":10737418240,"used":1073741824}`)
	case r.Method == "GET" && r.URL.EscapedPath() == "/fb/api/resources/My%20Docs/":
		io.WriteString(w, `{"path":"/My Docs/","name":"My Docs","isDir":true,"numDirs":1,"numFiles":1,"items":[
			{"path":"/My Docs/Old","name":"Old","isDir":true,"modified":"2026-11-01T00:00:00Z"},
			{"path":"/My Docs/a.txt","name":"a.txt","size":5,"isDir":false,"type":"text","modified":"2026-11-01T00:00:00Z","content":"LEAKME"}]}`)
	case r.Method == "GET" && r.URL.EscapedPath() == "/fb/api/resources/My%20Docs/a.txt":
		io.WriteString(w, `{"path":"/My Docs/a.txt","name":"a.txt","size":5,"isDir":false,"type":"text","content":"LEAKME"}`)
	case r.Method == "GET" && r.URL.Path == "/fb/api/search/":
		if r.URL.Query().Get("query") != "rep&ort" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `[{"dir":false,"path":"My Docs/report.pdf"}]`)
	case r.Method == "GET" && r.URL.Path == "/fb/api/shares":
		var parts []string
		for h, p := range f.shares {
			parts = append(parts, fmt.Sprintf(`{"hash":%q,"path":%q,"userID":1,"username":"alice","expire":0,"password_hash":"","token":"LEAKME"}`, h, p))
		}
		io.WriteString(w, "["+strings.Join(parts, ",")+"]")
	case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/fb/api/share/"):
		p := strings.TrimPrefix(r.URL.Path, "/fb/api/share")
		var parts []string
		for h, sp := range f.shares {
			if sp == p {
				parts = append(parts, fmt.Sprintf(`{"hash":%q,"path":%q,"userID":1,"expire":0}`, h, sp))
			}
		}
		if len(parts) == 0 {
			w.WriteHeader(404)
			return
		}
		io.WriteString(w, "["+strings.Join(parts, ",")+"]")
	case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/fb/api/share/"):
		f.n++
		h := fmt.Sprintf("Hash%04d", f.n)
		f.shares[h] = strings.TrimPrefix(r.URL.Path, "/fb/api/share")
		fmt.Fprintf(w, `{"hash":%q,"path":%q,"userID":1,"expire":0,"password_hash":"$2a$LEAKME","token":"LEAKME"}`, h, f.shares[h])
	case r.Method == "DELETE" && strings.HasPrefix(r.URL.Path, "/fb/api/share/"):
		delete(f.shares, strings.TrimPrefix(r.URL.Path, "/fb/api/share/"))
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, pw string) (*Module, *fakeFB) {
	f := &fakeFB{shares: map[string]string{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/fb", User: "alice", Password: pw})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://fb": "pw-LEAKME", "secret://bad": "wrong-LEAKME"}), "f", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "f", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestFileBrowser(t *testing.T) {
	m, f := setup(t, "secret://fb")
	if h := m.Health(context.Background(), "f"); h.Status != "ok" || !strings.Contains(h.Message, "1.0 GB of 10.0 GB used") {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"list", `{"path":"/My Docs"}`, `"name":"a.txt"`},
		{"search", `{"query":"rep&ort"}`, `"path":"My Docs/report.pdf"`},
		{"usage", `{}`, `"percent":10`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}
	if f.logins != 1 {
		t.Fatalf("signed in %d times", f.logins)
	}
	in := `{"path":"/My Docs/a.txt"}`
	r, err := invoke(m, "create_share", in, true)
	if err != nil || r.Plan == nil || len(f.shares) != 0 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "create_share", in, false)
	if err != nil || len(f.shares) != 1 || r.Undo == nil || r.Undo.Action != "delete_share" || strings.Contains(string(r.Output), "LEAKME") || !strings.Contains(string(r.Output), "/share/Hash0001") {
		t.Fatalf("%+v %v", r, err)
	}
	if strings.Contains(string(r.Undo.Input), "Hash") {
		t.Fatalf("undo holds the hash: %s", r.Undo.Input)
	}
	// The id is keyed with the password: a plain hash of the link's 6-byte
	// hash could be found by trying every one.
	plain := sha256.Sum256([]byte("filebrowser-share:Hash0001"))
	if strings.Contains(string(r.Undo.Input), hex.EncodeToString(plain[:12])) || !strings.Contains(string(r.Undo.Input), `"id":"l`) {
		t.Fatalf("undo id: %s", r.Undo.Input)
	}
	if r2, err := invoke(m, "create_share", in, false); err != nil || !strings.Contains(string(r2.Output), "nothing to change") || len(f.shares) != 1 {
		t.Fatalf("existing: %s %v", r2.Output, err)
	}
	if r2, err := invoke(m, "shares", `{}`, false); err != nil || strings.Contains(string(r2.Output), "LEAKME") || !strings.Contains(string(r2.Output), `"password":false`) {
		t.Fatalf("shares: %s %v", r2.Output, err)
	}
	if p, err := invoke(m, r.Undo.Action, string(r.Undo.Input), true); err != nil || p.Plan == nil || len(f.shares) != 1 {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || len(f.shares) != 0 {
		t.Fatal(err, f.shares)
	}
	if r2, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || !strings.Contains(string(r2.Output), "nothing to change") {
		t.Fatalf("%s %v", r2.Output, err)
	}
	for _, a := range m.Manifest().Actions {
		if strings.HasSuffix(a.Name, "_share") && a.Risk != sdk.RiskDestructive {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestFileBrowserValidation(t *testing.T) {
	m, f := setup(t, "secret://fb")
	for _, c := range []struct{ action, in string }{
		{"list", `{"path":"/a/../../etc"}`},
		{"list", `{"path":"etc"}`},
		{"list", `{"path":"/a\u0000b"}`},
		{"search", `{"query":""}`},
		{"search", `{"query":"a\nb"}`},
		{"create_share", `{"path":"/"}`},
		{"create_share", `{"path":"/x","expireHours":-3}`},
		{"delete_share", `{"id":"Hash0001"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 || f.logins != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{URL: "https://f.example.com", User: "a", Password: "plain"}, {URL: "f.example.com", User: "a", Password: "secret://fb"},
		{URL: "https://u:p@f.example.com", User: "a", Password: "secret://fb"}, {URL: "https://f.example.com/?x", User: "a", Password: "secret://fb"}, {URL: "https://f.example.com", Password: "secret://fb"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	h := bad.Health(context.Background(), "f")
	if h.Status != "down" || h.Message != "File Browser refused the user name or password" {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(bad, "list", `{}`, false); err == nil || strings.Contains(err.Error(), "LEAKME") {
		t.Fatal(err)
	}
}

func TestFileBrowserRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		leaked = r.Header.Get("X-Auth") + string(b)
	}))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/login" {
			io.WriteString(w, jwt)
			return
		}
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, User: "alice", Password: "secret://fb"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://fb": "pw"}), "f", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "f"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
